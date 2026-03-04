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
