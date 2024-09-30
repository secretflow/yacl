// Copyright 2019 Ant Group Co., Ltd.
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

#include "yacl/base/int128.h"

#include "gtest/gtest.h"

#include "yacl/crypto/rand/rand.h"

TEST(Int128Test, NumericLimitsTest) {
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Winteger-overflow"
#else
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverflow"
#endif
  EXPECT_EQ(std::numeric_limits<int128_t>::max() + 1,
            std::numeric_limits<int128_t>::min());
  EXPECT_EQ(std::numeric_limits<int128_t>::min() - 1,
            std::numeric_limits<int128_t>::max());
#ifdef __clang__
#pragma clang diagnostic pop
#else
#pragma GCC diagnostic pop
#endif
}

TEST(Uint128Test, NumericLimitsTest) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverflow"
  EXPECT_EQ(std::numeric_limits<uint128_t>::max() + 1,
            std::numeric_limits<uint128_t>::min());
  EXPECT_EQ(std::numeric_limits<uint128_t>::min() - 1,
            std::numeric_limits<uint128_t>::max());
#pragma GCC diagnostic pop
}

static_assert(std::is_integral_v<int128_t>);
static_assert(std::is_integral_v<uint128_t>);
static_assert(!std::is_floating_point_v<int128_t>);
static_assert(!std::is_floating_point_v<uint128_t>);

TEST(Int128Test, make_unsigned) {
  static_assert(std::is_same<std::make_unsigned_t<int128_t>, uint128_t>::value);
  static_assert(
      std::is_same<std::make_unsigned_t<uint128_t>, uint128_t>::value);
  static_assert(std::is_same<std::make_signed_t<int128_t>, int128_t>::value);
  static_assert(std::is_same<std::make_signed_t<uint128_t>, int128_t>::value);
}

TEST(Int128Test, Decompose) {
  {
    int128_t v = 1;
    auto parts = yacl::DecomposeInt128(v);
    EXPECT_EQ(v, yacl::MakeInt128(parts.first, parts.second));
  }
  {
    int128_t v = -1;
    auto parts = yacl::DecomposeInt128(v);
    EXPECT_EQ(v, yacl::MakeInt128(parts.first, parts.second));
  }
  {
    uint128_t v = 1;
    auto parts = yacl::DecomposeUInt128(v);
    EXPECT_EQ(v, yacl::MakeUint128(parts.first, parts.second));
  }
}

TEST(Int128Test, CountLzTest) {
  uint128_t x = 0;
  EXPECT_EQ(yacl::CountLZ(x), 128);

  x = 1;
  EXPECT_EQ(yacl::CountLZ(x), 127);

  x = yacl::crypto::FastRandU128();
  EXPECT_EQ(yacl::CountLZ(x), yacl::CountLZ(x));

  x = std::numeric_limits<uint128_t>::max();
  int offset = yacl::crypto::RandLtN(128);
  x >>= offset;
  EXPECT_EQ(yacl::CountLZ(x), offset);
}
