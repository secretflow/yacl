// Copyright 2024 Ant Group Co., Ltd.
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
// Group Element in 2n

#pragma once

#include <cstdint>
#include <type_traits>

#include "yacl/base/exception.h"
#include "yacl/base/int128.h"

namespace yacl::crypto {

template <size_t N /* bits numeber, as n in 2n */,
          typename StoreTy = uint128_t /* WARNING: DO NOT change StoreTy unless
                                          you kown what you're doing */
          ,
          std::enable_if_t<std::is_standard_layout<StoreTy>::value, int> = 0>
class GE2n {
 public:
  // Constructors
  GE2n() { static_assert(N <= sizeof(StoreTy) * 8); }
  explicit GE2n(StoreTy value) { store_ = value; }

  // Get the N-bit truncated value
  StoreTy GetVal() const { return store_ & kMask_; }

  // Get the N-bit mask
  StoreTy GetMask() const { return kMask_; }

  // Get the bit num of group
  size_t GetN() const { return N; }

  // Get the i-th least significant bit
  uint8_t GetBit(size_t i) const {
    YACL_ENFORCE(i < sizeof(StoreTy) * 8, "GetBit: index out of range");
    return store_ >> i & 1;
  }

  // Reverse a group element inplace
  void ReverseInplace() { store_ = kMask_ - GetVal() + 1; }

  // Get the reversed group element
  GE2n<N, StoreTy> GetReverse() const {
    return GE2n<N, StoreTy>(kMask_ - GetVal() + 1);
  }

  // supported operators
#define GE2N_OVERLOAD_BINARY_OP(OP)                                          \
  [[nodiscard]] GE2n<N, StoreTy> operator OP(GE2n<N, StoreTy> other) const { \
    return GE2n<N, StoreTy>(this->store_ OP other.store_);                   \
  }

  GE2N_OVERLOAD_BINARY_OP(+)
  GE2N_OVERLOAD_BINARY_OP(-)
#undef GE2N_OVERLOAD_BINARY_OP

  void operator+=(GE2n<N, StoreTy> other) { this->store_ += other.store_; }

  void operator-=(GE2n<N, StoreTy> other) { this->store_ -= other.store_; }

  [[nodiscard]] bool operator==(GE2n<N, StoreTy> other) const {
    return GetVal() == other.GetVal();
  }

  [[nodiscard]] bool operator!=(GE2n<N, StoreTy> other) const {
    return GetVal() != other.GetVal();
  }

  [[nodiscard]] bool operator>(GE2n<N, StoreTy> other) const {
    return GetVal() > other.GetVal();
  }

  [[nodiscard]] bool operator>=(GE2n<N, StoreTy> other) const {
    return GetVal() >= other.GetVal();
  }

  [[nodiscard]] bool operator<(GE2n<N, StoreTy> other) const {
    return GetVal() < other.GetVal();
  }

  [[nodiscard]] bool operator<=(GE2n<N, StoreTy> other) const {
    return GetVal() <= other.GetVal();
  }

 private:
  static constexpr StoreTy kMask_ =
      N == 128 ? Uint128Max() : (StoreTy(1) << N) - 1;
  StoreTy store_;
};

}  // namespace yacl::crypto
