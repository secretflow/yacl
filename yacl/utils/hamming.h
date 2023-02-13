// Copyright 2022 Ant Group Co., Ltd.
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

#include "absl/numeric/bits.h"
#include "absl/types/span.h"

#include "yacl/base/exception.h"
#include "yacl/base/int128.h"

namespace yacl {

// Reference: https://en.wikipedia.org/wiki/Hamming_weight
template <typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
inline constexpr size_t HammingWeight(T i) {
  if constexpr (sizeof(T) == 16) {
    // 128 bits
    auto low64 = static_cast<uint64_t>(i & ~uint64_t{0});
    auto high64 = static_cast<uint64_t>(i >> 64);
    return HammingWeight(low64) + HammingWeight(high64);
  } else {
    // TODO(shuyan.ycf): use `std::popcount` when we switch to c++20.
    return absl::popcount(i);
  }
}

template <typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
inline constexpr size_t HammingDistance(T x, T y) {
  return HammingWeight(x ^ y);
}

}  // namespace yacl
