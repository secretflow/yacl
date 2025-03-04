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

#include "yacl/crypto/experimental/dpf/dpf.h"

#include <future>
#include <iostream>

#include "gtest/gtest.h"

#include "yacl/base/int128.h"
#include "yacl/crypto/experimental/dpf/ge2n.h"
#include "yacl/crypto/rand/rand.h"

namespace yacl::crypto {

TEST(DpfTest, Gen) {
  DpfKey k0;
  DpfKey k1;
  uint128_t first_mk = SecureRandSeed();
  uint128_t second_mk = SecureRandSeed();

  constexpr size_t k_in_bitnum = 16;
  constexpr size_t k_out_bitnum = 64;

  auto alpha = GE2n<k_in_bitnum>(FastRandU64());
  auto beta = GE2n<k_out_bitnum>(FastRandU64());

  DpfKeyGen(&k0, &k1, alpha, beta, first_mk, second_mk, false);
}

TEST(DpfTest, Eval) {
  DpfKey k0;
  DpfKey k1;
  uint128_t first_mk = SecureRandSeed();
  uint128_t second_mk = SecureRandSeed();

  constexpr size_t k_in_bitnum = 16;
  constexpr size_t k_out_bitnum = 64;

  auto alpha = GE2n<k_in_bitnum>(FastRandU64());
  auto beta = GE2n<k_out_bitnum>(FastRandU64());

  DpfKeyGen(&k0, &k1, alpha, beta, first_mk, second_mk, false);

  /* wrong input */
  {
    auto in = GE2n<k_in_bitnum>(FastRandU64());
    while (in == alpha) {
      in = GE2n<k_in_bitnum>(FastRandU64());
    }
    auto out1 = GE2n<k_out_bitnum>(0);
    auto out2 = GE2n<k_out_bitnum>(0);
    DpfEval(k0, in, &out1);
    DpfEval(k1, in, &out2);
    EXPECT_EQ((out1 + out2).GetVal(), 0);
  }

  /* correct input */
  {
    auto out1 = GE2n<k_out_bitnum>(0);
    auto out2 = GE2n<k_out_bitnum>(0);
    DpfEval(k0, alpha, &out1);
    DpfEval(k1, alpha, &out2);
    EXPECT_EQ(out1 + out2, beta);
  }
}

TEST(DpfTest, EvalAll) {
  DpfKey k0;
  DpfKey k1;
  uint128_t first_mk = SecureRandSeed();
  uint128_t second_mk = SecureRandSeed();

  constexpr size_t k_in_bitnum = 16;
  constexpr size_t k_out_bitnum = 128;

  auto alpha = GE2n<k_in_bitnum>(FastRandU64());
  auto beta = GE2n<k_out_bitnum>(FastRandU64());

  DpfKeyGen(&k0, &k1, alpha, beta, first_mk, second_mk, true);

  size_t range = 1 << k_in_bitnum;
  auto out1 = std::vector<GE2n<k_out_bitnum>>(range);
  auto out2 = std::vector<GE2n<k_out_bitnum>>(range);
  DpfEvalAll<k_in_bitnum, k_out_bitnum>(&k0, absl::MakeSpan(out1));
  DpfEvalAll<k_in_bitnum, k_out_bitnum>(&k1, absl::MakeSpan(out2));

  for (size_t i = 0; i < range; i++) {
    auto result = out1[i] + out2[i];

    if (i == alpha.GetVal()) {
      EXPECT_EQ(result, beta);
    } else {
      EXPECT_EQ(result.GetVal(), 0);
    }
  }
}

}  // namespace yacl::crypto
