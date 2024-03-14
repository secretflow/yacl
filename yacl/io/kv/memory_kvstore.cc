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

#include "yacl/io/kv/memory_kvstore.h"

#include <utility>

namespace yacl::io {

void MemoryKVStore::Put(absl::string_view key, ByteContainerView value) {
  Buffer value_vec(value.size());

  std::memcpy(value_vec.data(), value.data(), value.size());
  kv_map.insert(std::make_pair(key, value_vec));
}

bool MemoryKVStore::Get(absl::string_view key, std::string *value) const {
  auto it = kv_map.find(
      static_cast<std::basic_string<char, std::char_traits<char>>>(key));
  if (it != kv_map.end()) {
    value->assign((const char *)it->second.data(), it->second.size());
    return true;
  }

  return false;
}

size_t MemoryKVStore::Count() const { return kv_map.size(); }

}  // namespace yacl::io
