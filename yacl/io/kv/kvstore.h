// Copyright (c) 2021 Ant Financial. All rights reserved.

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
  virtual bool Get(absl::string_view key, Buffer *value) const = 0;

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
  bool Get(size_t index, Buffer *value) {
    return kv_store_->Get(std::to_string(index), value);
  }

  size_t Count() const { return kv_store_->Count(); }

 private:
  std::shared_ptr<KVStore> kv_store_;
};

}  // namespace yacl::io
