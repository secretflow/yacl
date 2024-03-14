// Copyright 2021 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
        SPDLOG_INFO("Delete tmp file:{} exception {}", path_,
                    std::string(e.what()));
      }
    }
    is_open_ = false;
  }
}

void LeveldbKVStore::Put(absl::string_view key, ByteContainerView value) {
  leveldb::Slice key_slice(key.data(), key.length());
  leveldb::Slice data_slice((const char *)value.data(), value.size());

  leveldb::Status db_status =
      db_->Put(leveldb::WriteOptions(), key_slice, data_slice);

  if (!db_status.ok()) {
    YACL_THROW("Put key:{} error, {}", key, db_status.ToString());
  }
}

bool LeveldbKVStore::Get(absl::string_view key, std::string *value) const {
  leveldb::Status db_status = db_->Get(
      leveldb::ReadOptions(),
      static_cast<std::basic_string<char, std::char_traits<char>>>(key), value);

  if (!db_status.ok()) {
    if (db_status.IsNotFound()) {
      SPDLOG_INFO("key not found");
      return false;
    }
    SPDLOG_ERROR("Get key: {}, error: {}", key, db_status.ToString());
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
