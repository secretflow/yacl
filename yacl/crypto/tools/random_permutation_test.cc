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

#include "yacl/crypto/tools/random_permutation.h"

#include <algorithm>
#include <random>

#include "gtest/gtest.h"

#include "yacl/base/exception.h"
#include "yacl/crypto/tools/prg.h"

namespace yacl::crypto {

namespace {
inline auto RandomBlocks(size_t length) {
  std::vector<uint128_t> rand_inputs(length);
  Prg<uint128_t> prg;
  prg.Fill(absl::MakeSpan(rand_inputs));
  return rand_inputs;
}

inline auto RandomU128() {
  Prg<uint128_t> prg(0, PRG_MODE::kNistAesCtrDrbg);
  return prg();
}

}  // namespace

TEST(RandomPermTest, U128Works) {
  const auto& RP = RandomPerm::GetDefault();

  auto input = RandomU128();

  EXPECT_EQ(RP.Gen(input), RP.Gen(input));
}

TEST(RandomPermTest, BlocksWorks) {
  const auto& RP = RandomPerm::GetDefault();

  auto input = RandomBlocks(20);

  EXPECT_EQ(RP.Gen(absl::MakeSpan(input)), RP.Gen(absl::MakeSpan(input)));
}

TEST(RandomPermTest, CrHashWorks) {
  const size_t x = RandomU128();
  const size_t y = RandomU128();

  EXPECT_NE(CrHash_128(x), 0);
  EXPECT_EQ(CrHash_128(x), CrHash_128(x));
  EXPECT_NE(CrHash_128(x), CrHash_128(y));
}

TEST(RandomPermTest, ParaCrHashWorks) {
  const auto size = 20;

  std::vector<uint128_t> zeros(size, 0);
  auto input = RandomBlocks(size);
  auto output = ParaCrHash_128(absl::MakeSpan(input));

  EXPECT_NE(absl::MakeSpan(output), absl::MakeSpan(zeros));
  EXPECT_NE(absl::MakeSpan(output), absl::MakeSpan(input));
  EXPECT_EQ(absl::MakeSpan(output), ParaCrHash_128(absl::MakeSpan(input)));
}

TEST(RandomPermTest, ParaCrHashInplaceWorks) {
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

}  // namespace yacl::crypto
