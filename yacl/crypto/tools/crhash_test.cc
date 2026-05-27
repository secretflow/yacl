// Copyright 2021 Ant Group Co., Ltd.
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

#include "yacl/crypto/tools/crhash.h"

#include <algorithm>

#include "gtest/gtest.h"

#include "yacl/base/exception.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/crypto/tools/prg.h"

namespace yacl::crypto {

namespace {
inline auto RandomBlocks(size_t length) {
  std::vector<uint128_t> rand_inputs(length);
  Prg<uint128_t> prg;
  prg.Fill<uint128_t>(absl::MakeSpan(rand_inputs));
  return rand_inputs;
}

}  // namespace

TEST(RPTest, CrHashWorks) {
  uint128_t x = FastRandU128();
  uint128_t y = FastRandU128();

  EXPECT_NE(x, y);
  EXPECT_NE(CrHash_128(x), 0);
  EXPECT_EQ(CrHash_128(x), CrHash_128(x));
  EXPECT_NE(CrHash_128(x), CrHash_128(y));
}

TEST(RPTest, ParaCrHashWorks) {
  const auto size = 20;

  std::vector<uint128_t> zeros(size, 0);
  auto input = RandomBlocks(size);
  auto output = ParaCrHash_128(absl::MakeSpan(input));

  EXPECT_NE(absl::MakeSpan(output), absl::MakeSpan(zeros));
  EXPECT_NE(absl::MakeSpan(output), absl::MakeSpan(input));
  EXPECT_EQ(absl::MakeSpan(output), ParaCrHash_128(absl::MakeSpan(input)));
}

TEST(RPTest, ParaCrHashInplaceWorks) {
  const auto size = 20;

  std::vector<uint128_t> zeros(size, 0);
  auto inout = RandomBlocks(size);
  auto inout_copy = inout;

  ParaCrHashInplace_128(absl::MakeSpan(inout));
  EXPECT_NE(absl::MakeSpan(inout), absl::MakeSpan(zeros));
  EXPECT_NE(absl::MakeSpan(inout), absl::MakeSpan(inout_copy));

  ParaCrHashInplace_128(absl::MakeSpan(inout_copy));
  EXPECT_EQ(absl::MakeSpan(inout), absl::MakeSpan(inout_copy));
}

TEST(RPTest, CcrHashWorks) {
  const uint128_t x = FastRandU128();
  const uint128_t y = FastRandU128();

  EXPECT_NE(x, y);
  EXPECT_NE(CcrHash_128(x), 0);
  EXPECT_EQ(CcrHash_128(x), CcrHash_128(x));
  EXPECT_NE(CcrHash_128(x), CcrHash_128(y));
}

TEST(RPTest, ParaCcrHashWorks) {
  const auto size = 20;

  std::vector<uint128_t> zeros(size, 0);
  auto input = RandomBlocks(size);
  auto output = ParaCcrHash_128(absl::MakeSpan(input));

  EXPECT_NE(absl::MakeSpan(output), absl::MakeSpan(zeros));
  EXPECT_NE(absl::MakeSpan(output), absl::MakeSpan(input));
  EXPECT_EQ(absl::MakeSpan(output), ParaCcrHash_128(absl::MakeSpan(input)));
}

TEST(RPTest, ParaCcrHashInplaceWorks) {
  const auto size = 20;

  std::vector<uint128_t> zeros(size, 0);
  auto inout = RandomBlocks(size);
  auto inout_copy = inout;

  ParaCcrHashInplace_128(absl::MakeSpan(inout));
  EXPECT_NE(absl::MakeSpan(inout), absl::MakeSpan(zeros));
  EXPECT_NE(absl::MakeSpan(inout), absl::MakeSpan(inout_copy));

  ParaCcrHashInplace_128(absl::MakeSpan(inout_copy));
  EXPECT_EQ(absl::MakeSpan(inout), absl::MakeSpan(inout_copy));
}

}  // namespace yacl::crypto
