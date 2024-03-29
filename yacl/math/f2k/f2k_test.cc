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

#include "yacl/math/f2k/f2k.h"

#include <cstdint>
#include <iostream>
#include <utility>
#include <vector>

#include "gtest/gtest.h"

#include "yacl/base/block.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/rand/rand.h"

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
#define MULTEST(type, range, x0, x1, y0, y1) \
  auto x = x0 ^ x1;                          \
  auto y = y0 ^ y1;                          \
  auto xy = yacl::type##Mul##range(x, y);    \
  auto yx = yacl::type##Mul##range(y, x);    \
  auto zero = xy ^ xy;                       \
  EXPECT_EQ(xy, yx);                         \
  auto xy0 = yacl::type##Mul##range(x, y0);  \
  auto xy1 = yacl::type##Mul##range(x, y1);  \
  EXPECT_EQ(xy, xy0 ^ xy1);                  \
  auto x0y = yacl::type##Mul##range(x0, y);  \
  auto x1y = yacl::type##Mul##range(x1, y);  \
  EXPECT_EQ(xy, x0y ^ x1y);                  \
  EXPECT_NE(zero, xy);                       \
  EXPECT_NE(zero, yx);
}  // namespace

TEST(F2kTest, ClMul128_block) {
  auto t = yacl::crypto::RandVec<yacl::block>(4);
  MULTEST(Cl, 128, t[0], t[1], t[2], t[3]);
}

TEST(F2kTest, ClMul128) {
  auto t = yacl::crypto::RandVec<uint128_t>(4);
  MULTEST(Cl, 128, t[0], t[1], t[2], t[3]);
}

TEST(F2kTest, ClMul64) {
  auto t = yacl::crypto::RandVec<uint64_t>(4);
  MULTEST(Cl, 64, t[0], t[1], t[2], t[3]);
}

TEST(F2kTest, GfMul128_block) {
  auto t = yacl::crypto::RandVec<yacl::block>(4);
  MULTEST(Gf, 128, t[0], t[1], t[2], t[3]);
}

TEST(F2kTest, GfMul128) {
  auto t = yacl::crypto::RandVec<uint128_t>(4);
  MULTEST(Gf, 128, t[0], t[1], t[2], t[3]);
}

TEST(F2kTest, GfMul64) {
  auto t = yacl::crypto::RandVec<uint64_t>(4);
  MULTEST(Gf, 64, t[0], t[1], t[2], t[3]);
}

TEST(F2kTest, GfMul128_inner_product) {
  const uint64_t size = 1001;
  auto zero = uint128_t(0);

  auto x = yacl::crypto::RandVec<uint128_t>(size);
  auto y = yacl::crypto::RandVec<uint128_t>(size);
  auto x_span = absl::MakeSpan(x);
  auto y_span = absl::MakeSpan(y);

  auto ret = yacl::GfMul128(x_span, y_span);

  uint128_t check = 0;
  for (uint64_t i = 0; i < size; ++i) {
    check ^= yacl::GfMul128(x[i], y[i]);
  }

  EXPECT_EQ(ret, check);
  EXPECT_NE(ret, zero);
}

TEST(F2kTest, GfMul64_inner_product) {
  const uint64_t size = 1001;
  uint64_t zero = 0;

  auto x = yacl::crypto::RandVec<uint64_t>(size);
  auto y = yacl::crypto::RandVec<uint64_t>(size);
  auto x_span = absl::MakeSpan(x);
  auto y_span = absl::MakeSpan(y);

  auto ret = yacl::GfMul64(x_span, y_span);

  uint64_t check = 0;
  for (uint64_t i = 0; i < size; ++i) {
    check ^= yacl::GfMul64(x[i], y[i]);
  }

  EXPECT_EQ(ret, check);
  EXPECT_NE(ret, zero);
}

TEST(F2kTest, GfInv64_inner_product) {
  const uint64_t size = 1001;

  auto x = yacl::crypto::RandVec<uint64_t>(size);
  for (uint64_t i = 0; i < size; ++i) {
    auto inv = yacl::GfInv64(x[i]);
    auto check = yacl::GfMul64(x[i], inv);
    EXPECT_EQ(uint64_t(1), check);
  }
}