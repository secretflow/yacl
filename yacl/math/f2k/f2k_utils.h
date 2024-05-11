// Copyright 2023 Ant Group Co., Ltd.
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

#include "yacl/base/aligned_vector.h"
#include "yacl/math/f2k/f2k.h"
#include "yacl/math/gadget.h"

namespace yacl::math {

// ------------------------
//   f2k-field operation
// ------------------------

// inner-product
uint128_t inline GfMul(absl::Span<const uint128_t> a,
                       absl::Span<const uint128_t> b) {
  return GfMul128(a, b);
}

uint64_t inline GfMul(absl::Span<const uint64_t> a,
                      absl::Span<const uint64_t> b) {
  return GfMul64(a, b);
}

uint128_t inline GfMul(absl::Span<const uint128_t> a,
                       absl::Span<const uint64_t> b) {
  UninitAlignedVector<uint128_t> tmp(b.size());
  std::transform(b.cbegin(), b.cend(), tmp.begin(), [](const uint64_t& val) {
    return static_cast<uint128_t>(val);
  });
  return GfMul128(a, absl::MakeSpan(tmp));
}

uint128_t inline GfMul(absl::Span<const uint64_t> a,
                       absl::Span<const uint128_t> b) {
  return GfMul(b, a);
}

// element-wise
uint128_t inline GfMul(uint128_t a, uint128_t b) { return GfMul128(a, b); }

uint64_t inline GfMul(uint64_t a, uint64_t b) { return GfMul64(a, b); }

uint128_t inline GfMul(uint128_t a, uint64_t b) {
  return GfMul128(a, static_cast<uint128_t>(b));
}

uint128_t inline GfMul(uint64_t a, uint128_t b) {
  return GfMul128(static_cast<uint128_t>(a), b);
}

// ------------------------
//   f2k-Universal Hash
// ------------------------

// see difference between universal hash and collision-resistent hash functions:
// https://crypto.stackexchange.com/a/88247/61581
template <typename T>
T UniversalHash(T seed, absl::Span<const T> data) {
  T ret = 0;
  for_each(data.rbegin(), data.rend(), [&ret, &seed](const T& val) {
    ret ^= val;
    ret = GfMul(seed, ret);
  });
  return ret;
}

template <typename T>
std::vector<T> ExtractHashCoef(T seed,
                               absl::Span<const uint64_t> indexes /*sorted*/) {
  std::array<T, 64> buff = {};
  auto max_bits = math::Log2Ceil(indexes.back());
  buff[0] = seed;
  for (size_t i = 1; i <= max_bits; ++i) {
    buff[i] = GfMul(buff[i - 1], buff[i - 1]);
  }

  std::vector<T> ret;
  for (const auto& index : indexes) {
    auto index_plus_one = index + 1;
    uint64_t mask = 1;
    T coef = 1;
    for (size_t i = 0; i < 64 && mask <= index_plus_one; ++i) {
      if (mask & index_plus_one) {
        coef = GfMul(coef, buff[i]);
      }
      mask <<= 1;
    }
    ret.push_back(coef);
  }
  return ret;
}

}  // namespace yacl::math