// Copyright 2023 Ant Group Co., Ltd.
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

#include "yacl/math/galois_field/gf_intrinsic.h"

#include <cstdint>
#include <iostream>
#include <utility>
#include <vector>

#include "gtest/gtest.h"

#include "yacl/base/block.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/rand/rand.h"

namespace yacl::math {

namespace {
template <class T>
bool operator==(const std::pair<T, T>& lhs, const std::pair<T, T>& rhs) {
  return lhs.first == rhs.first && lhs.second == rhs.second;
}

template <class T>
bool operator!=(const std::pair<T, T>& lhs, const std::pair<T, T>& rhs) {
  return (lhs.first != rhs.first) || (lhs.second != rhs.second);
}

template <class T>
std::pair<T, T> operator^(const std::pair<T, T>& lhs,
                          const std::pair<T, T>& rhs) {
  return std::make_pair(lhs.first ^ rhs.first, lhs.second ^ rhs.second);
}

// check commutative property over F2k
#define GF_MUL_TEST(FUNC, T)              \
  {                                       \
    auto x = yacl::crypto::RandVec<T>(2); \
    auto y = yacl::crypto::RandVec<T>(2); \
    auto x_sum = x[0] ^ x[1];             \
    auto y_sum = y[0] ^ y[1];             \
    T xy;                                 \
    T yx;                                 \
    {                                     \
      FUNC(x_sum, y_sum, &xy);            \
      FUNC(y_sum, x_sum, &yx);            \
      EXPECT_EQ(xy, yx);                  \
    }                                     \
    auto zero = xy ^ xy;                  \
    {                                     \
      T xy0;                              \
      T xy1;                              \
      FUNC(x_sum, y[0], &xy0);            \
      FUNC(x_sum, y[1], &xy1);            \
      EXPECT_EQ(xy, xy0 ^ xy1);           \
    }                                     \
    {                                     \
      T x0y;                              \
      T x1y;                              \
      FUNC(x[0], y_sum, &x0y);            \
      FUNC(x[1], y_sum, &x1y);            \
      EXPECT_EQ(xy, x0y ^ x1y);           \
      EXPECT_NE(zero, xy);                \
      EXPECT_NE(zero, yx);                \
    }                                     \
  }
}  // namespace

TEST(GFTest, Mul128) {
  GF_MUL_TEST(Gf128Mul, block);
  GF_MUL_TEST(Gf128Mul, uint128_t);
}

TEST(GFTest, Mul64) { GF_MUL_TEST(Gf64Mul, uint64_t); }

TEST(GFTest, Gf128_inner_product) {
  const uint64_t size = 1001;
  auto zero = uint128_t(0);

  auto x = yacl::crypto::RandVec<uint128_t>(size);
  auto y = yacl::crypto::RandVec<uint128_t>(size);
  auto x_span = absl::MakeSpan(x);
  auto y_span = absl::MakeSpan(y);
  uint128_t ret;

  Gf128Mul(x_span, y_span, &ret);

  uint128_t check = 0;
  for (uint64_t i = 0; i < size; ++i) {
    uint128_t temp;
    Gf128Mul(x[i], y[i], &temp);
    check ^= temp;
  }

  EXPECT_EQ(ret, check);
  EXPECT_NE(ret, zero);
}

TEST(GFTest, Gf64_inner_product) {
  const uint64_t size = 1001;
  uint64_t zero = 0;

  auto x = yacl::crypto::RandVec<uint64_t>(size);
  auto y = yacl::crypto::RandVec<uint64_t>(size);
  auto x_span = absl::MakeSpan(x);
  auto y_span = absl::MakeSpan(y);

  uint64_t ret;
  Gf64Mul(x_span, y_span, &ret);

  uint64_t check = 0;
  for (uint64_t i = 0; i < size; ++i) {
    uint64_t temp;
    Gf64Mul(x[i], y[i], &temp);
    check ^= temp;
  }

  EXPECT_EQ(ret, check);
  EXPECT_NE(ret, zero);
}

TEST(GFTest, GfInv64_inner_product) {
  const uint64_t size = 1001;

  auto x = yacl::crypto::RandVec<uint64_t>(size);
  for (uint64_t i = 0; i < size; ++i) {
    uint64_t x_inv;
    Gf64Inv(x[i], &x_inv);
    uint64_t check;
    Gf64Mul(x[i], x_inv, &check);
    EXPECT_EQ(uint64_t(1), check);
  }
}

}  // namespace yacl::math
