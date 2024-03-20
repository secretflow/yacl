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

#include "yacl/crypto/tools/rp.h"

#include <algorithm>
#include <random>

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

TEST(RPTest, U128Works) {
  const auto& RP = RP::GetDefault();

  auto input = FastRandU128();

  EXPECT_EQ(RP.Gen(input), RP.Gen(input));
}

TEST(RPTest, BlocksWorks) {
  const auto& RP = RP::GetDefault();

  auto input = RandomBlocks(20);

  EXPECT_EQ(RP.Gen(absl::MakeSpan(input)), RP.Gen(absl::MakeSpan(input)));
}

}  // namespace yacl::crypto
