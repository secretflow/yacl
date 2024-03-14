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

#include <map>
#include <string>
#include <vector>

#include "yacl/io/kv/kvstore.h"

namespace yacl::io {

class MemoryKVStore : public KVStore {
 public:
  void Put(absl::string_view key, ByteContainerView value) override;
  bool Get(absl::string_view key, std::string *value) const override;

  size_t Count() const override;

 private:
  std::map<std::string, Buffer> kv_map;
};

}  // namespace yacl::io
