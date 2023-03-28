// Copyright (c) 2021 Ant Financial. All rights reserved.

#include "yacl/io/kv/memory_kvstore.h"

#include <utility>

namespace yacl::io {

void MemoryKVStore::Put(absl::string_view key, ByteContainerView value) {
  Buffer value_vec(value.size());

  std::memcpy(value_vec.data(), value.data(), value.size());
  kv_map.insert(std::make_pair(key, value_vec));
}

bool MemoryKVStore::Get(absl::string_view key, Buffer *value) const {
  auto it = kv_map.find(
      static_cast<std::basic_string<char, std::char_traits<char>>>(key));
  if (it != kv_map.end()) {
    (*value).resize(it->second.size());
    std::memcpy((*value).data(), it->second.data(), it->second.size());
    return true;
  }

  return false;
}

size_t MemoryKVStore::Count() const { return kv_map.size(); }

}  // namespace yacl::io
