// Copyright 2026 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <unordered_map>
#include <vector>

#include "yacl/crypto/experimental/threshold_ecdsa/common/bytes.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/scalar.h"

namespace tecdsa {

inline void SecureZeroizeMemory(void* data, size_t size) noexcept {
  if (data == nullptr || size == 0) {
    return;
  }

  volatile uint8_t* ptr = static_cast<volatile uint8_t*>(data);
  while (size > 0) {
    *ptr = 0;
    ++ptr;
    --size;
  }
}

inline void SecureZeroize(Bytes* value) noexcept {
  if (value == nullptr) {
    return;
  }
  if (!value->empty()) {
    SecureZeroizeMemory(value->data(), value->size());
  }
  value->clear();
}

inline void SecureZeroize(Scalar* value) noexcept {
  if (value == nullptr) {
    return;
  }
  *value = Scalar();
}

inline void SecureZeroize(std::optional<Scalar>* value) noexcept {
  if (value == nullptr) {
    return;
  }
  if (value->has_value()) {
    SecureZeroize(&value->value());
  }
  value->reset();
}

inline void SecureZeroize(std::vector<Scalar>* values) noexcept {
  if (values == nullptr) {
    return;
  }
  for (Scalar& value : *values) {
    SecureZeroize(&value);
  }
  values->clear();
}

template <typename K>
inline void SecureZeroize(std::unordered_map<K, Scalar>* values) noexcept {
  if (values == nullptr) {
    return;
  }
  for (auto& [key, value] : *values) {
    (void)key;
    SecureZeroize(&value);
  }
  values->clear();
}

template <typename K>
inline void SecureZeroize(std::unordered_map<K, Bytes>* values) noexcept {
  if (values == nullptr) {
    return;
  }
  for (auto& [key, value] : *values) {
    (void)key;
    SecureZeroize(&value);
  }
  values->clear();
}

}  // namespace tecdsa
