// Copyright (c) 2021 Ant Financial. All rights reserved.

#include "yacl/io/kv/leveldb_kvstore.h"

#include "butil/file_util.h"
#include "butil/files/temp_file.h"
#include "butil/strings/string_split.h"
#include "butil/strings/string_util.h"
#include "spdlog/spdlog.h"

#include "yacl/base/exception.h"

namespace yacl::io {

LeveldbKVStore::LeveldbKVStore(bool is_temp, const std::string &file_path)
    : is_temp_(is_temp) {
  leveldb::Options options;
  options.create_if_missing = true;

  std::string db_path = file_path;
  if (db_path.empty()) {
    butil::TempFile temp_file;
    db_path = std::string(temp_file.fname());
  }

  leveldb::DB *db_ptr = nullptr;
  leveldb::Status db_status = leveldb::DB::Open(options, db_path, &db_ptr);
  YACL_ENFORCE(db_status.ok(), "leveldb open failed, msg: {}",
               db_status.ToString());
  db_.reset(db_ptr);
  path_ = db_path;
  is_open_ = true;
}

LeveldbKVStore::~LeveldbKVStore() {
  if (is_open_) {
    // this is a temporary db.
    // delete db before remove it from disk.
    if (db_) delete db_.release();
    if (is_temp_) {
      try {
        butil::FilePath file_path(path_);
        butil::DeleteFile(file_path, true);
      } catch (const std::exception &e) {
        // Nothing we can do here.
        SPDLOG_INFO("Delete tmp file:{} exception {}", path_, e.what());
      }
    }
    is_open_ = false;
  }
}

void LeveldbKVStore::Put(absl::string_view key, ByteContainerView value) {
  std::string value_str(value.size(), '\0');
  std::memcpy(&value_str[0], value.data(), value.size());

  leveldb::Status db_status = db_->Put(
      leveldb::WriteOptions(),
      static_cast<std::basic_string<char, std::char_traits<char>>>(key),
      value_str);

  if (!db_status.ok()) {
    YACL_THROW("Put key:{} error, {}", db_status.ToString());
  }
}

bool LeveldbKVStore::Get(absl::string_view key, Buffer *value) const {
  std::string value_str;
  leveldb::Status db_status = db_->Get(
      leveldb::ReadOptions(),
      static_cast<std::basic_string<char, std::char_traits<char>>>(key),
      &value_str);

  (*value).resize(value_str.size());
  std::memcpy((*value).data(), &value_str[0], value_str.size());

  if (!db_status.ok()) {
    if (db_status.IsNotFound()) {
      SPDLOG_INFO("key not found");
      return false;
    }
    SPDLOG_ERROR("Get key: {}, error:", key, db_status.ToString());
    return false;
  }
  return true;
}

size_t LeveldbKVStore::Count() const {
  size_t count = 0;

  leveldb::Iterator *it = db_->NewIterator(leveldb::ReadOptions());
  for (it->SeekToFirst(); it->Valid(); it->Next()) {
    count++;
  }

  YACL_ENFORCE(it->status().ok());

  delete it;

  return count;
}

}  // namespace yacl::io
