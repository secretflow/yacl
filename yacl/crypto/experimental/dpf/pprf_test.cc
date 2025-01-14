// Copyright 2024 Ant Group Co., Ltd.
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

#include "yacl/crypto/experimental/dpf/pprf.h"

#include "gtest/gtest.h"

#include "yacl/base/exception.h"
#include "yacl/crypto/rand/rand.h"

namespace yacl::crypto {

TEST(PprfTest, Works) {
  /* GIVEN */
  constexpr size_t M = 2;
  constexpr size_t N = 128;

  size_t num = 1 << M;
  uint128_t punc_point = RandInRange(M);
  auto prf_key = SecureRandSeed();
  PprfPuncKey punc_key;
  PprfPunc<M, N>(prf_key, punc_point, &punc_key);

  GE2n<N> out1;
  GE2n<N> out2;
  for (size_t i = 0; i < num; ++i) {
    if (i != punc_point) {
      /* WHEN */
      PprfEval<M, N>(prf_key, i, &out1);
      PprfPuncEval<M, N>(punc_key, i, &out2);

      /* THEN */
      EXPECT_EQ(out1.GetVal(), out2.GetVal());
    }
  }
}

}  // namespace yacl::crypto
