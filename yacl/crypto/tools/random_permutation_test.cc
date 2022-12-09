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

namespace yacl {

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

}  // namespace yacl
