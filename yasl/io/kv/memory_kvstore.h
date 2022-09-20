// Copyright (c) 2021 Ant Financial. All rights reserved.

#pragma once

#include <map>
#include <string>
#include <vector>

#include "yasl/io/kv/kvstore.h"

namespace yasl::io {

class MemoryKVStore : public KVStore {
 public:
  void Put(absl::string_view key, ByteContainerView value) override;
  bool Get(absl::string_view key, Buffer *value) const override;

 private:
  std::map<std::string, Buffer> kv_map;
};

}  // namespace yasl::io
