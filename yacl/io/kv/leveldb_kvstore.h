// Copyright (c) 2021 Ant Financial. All rights reserved.

#pragma once

#include <memory>
#include <string>
#include <vector>

#include "leveldb/db.h"

#include "yacl/io/kv/kvstore.h"

namespace yacl::io {

class LeveldbKVStore : public KVStore {
 public:
  // give empty file_path create a temp kvstore
  // class destructor will delete the temp file
  // give not empty file_path, destructor will not delete file
  explicit LeveldbKVStore(bool is_temp, const std::string &file_path = "");

  ~LeveldbKVStore() override;

  void Put(absl::string_view key, ByteContainerView value) override;

  bool Get(absl::string_view key, Buffer *value) const override;

  size_t Count() const override;

 private:
  std::string path_;

  bool is_open_ = false;
  bool is_temp_;

  std::unique_ptr<leveldb::DB> db_;
};

}  // namespace yacl::io
