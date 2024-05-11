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

#include "yacl/kernel/code/linear_code.h"

#include <vector>

#include "gtest/gtest.h"

#include "yacl/crypto/rand/rand.h"

namespace yacl::crypto {

TEST(Llc, LlcWorks) {
  // GIVEN
  uint128_t seed = FastRandSeed();
  uint32_t n = 102400;
  uint32_t k = 1024;
  LocalLinearCode<10> llc(seed, n, k);
  LocalLinearCode<10> dup_llc(seed, n, k);
  auto input = RandVec<uint128_t>(k);
  std::vector<uint128_t> out(n);
  std::vector<uint128_t> check(n);
  std::vector<uint128_t> check1(n);
  std::vector<uint128_t> check2(n);
  // WHEN
  llc.Encode(input, absl::MakeSpan(out));
  dup_llc.Encode(input, absl::MakeSpan(check));
  llc.Encode2(input, absl::MakeSpan(check1), input, absl::MakeSpan(check2));

  uint32_t zero_counter = 0;
  for (uint32_t i = 0; i < n; ++i) {
    EXPECT_EQ(out[i], check[i]);
    EXPECT_EQ(out[i], check1[i]);
    EXPECT_EQ(out[i], check2[i]);
    if (out[i] == 0) {
      zero_counter++;
    }
  }

  EXPECT_LE(zero_counter, 2);
}

}  // namespace yacl::crypto
