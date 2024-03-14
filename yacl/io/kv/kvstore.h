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

#include "absl/strings/string_view.h"

#include "yacl/base/buffer.h"
#include "yacl/base/byte_container_view.h"

namespace yacl::io {

class KVStore {
 public:
  virtual ~KVStore() = default;

  // store key,value
  virtual void Put(absl::string_view key, ByteContainerView value) = 0;

  // get value by key
  virtual bool Get(absl::string_view key, std::string *value) const = 0;

  // get value by key
  bool Get(absl::string_view key, Buffer *value) const {
    std::string value_str;
    bool ret = Get(key, &value_str);

    value->resize(value_str.length());
    std::memcpy(value->data(), value_str.data(), value_str.length());

    return ret;
  }

  // get count
  virtual size_t Count() const = 0;
};

class IndexStore {
 public:
  explicit IndexStore(const std::shared_ptr<KVStore> &kv_store)
      : kv_store_(kv_store) {}

  // store index,value
  void Put(size_t index, ByteContainerView value) {
    kv_store_->Put(std::to_string(index), value);
  }

  // get value by index
  bool Get(size_t index, std::string *value) const {
    return kv_store_->Get(std::to_string(index), value);
  }

  // get value by key
  bool Get(size_t index, Buffer *value) const {
    return kv_store_->Get(std::to_string(index), value);
  }

  size_t Count() const { return kv_store_->Count(); }

 private:
  std::shared_ptr<KVStore> kv_store_;
};

}  // namespace yacl::io
