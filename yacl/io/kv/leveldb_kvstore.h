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

  bool Get(absl::string_view key, std::string *value) const override;

  size_t Count() const override;

 private:
  std::string path_;

  bool is_open_ = false;
  bool is_temp_;

  std::unique_ptr<leveldb::DB> db_;
};

}  // namespace yacl::io
