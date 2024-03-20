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

#include "yacl/crypto/dpf/dpf.h"

#include <future>
#include <iostream>

#include "gtest/gtest.h"

namespace yacl::crypto {

struct TestParams {
  DpfInStore alpha;
  DpfOutStore beta;
  uint32_t InBitnum;
  uint32_t SsBitnum;
};

class FssDpfGenTest : public testing::TestWithParam<TestParams> {};

class FssDpfEvalTest : public testing::TestWithParam<TestParams> {};

class FssDpfEvalAllTest : public testing::TestWithParam<TestParams> {};

TEST_P(FssDpfGenTest, Works) {
  auto params = GetParam();
  DpfKey k0, k1;
  uint128_t first_mk = 0;
  uint128_t second_mk = 1;
  DpfContext context;
  context.SetInBitNum(params.InBitnum);
  context.SetSsBitNum(params.SsBitnum);

  std::tie(k0, k1) =
      context.Gen(params.alpha, params.beta, first_mk, second_mk, false);
}

TEST_P(FssDpfEvalTest, Works) {
  auto params = GetParam();
  DpfKey k0;
  DpfKey k1;
  DpfContext context;
  uint128_t first_mk = 0;
  uint128_t second_mk = 1;

  context.SetInBitNum(params.InBitnum);
  context.SetSsBitNum(params.SsBitnum);

  std::tie(k0, k1) =
      context.Gen(params.alpha, params.beta, first_mk, second_mk, false);

  size_t range = 1 << context.GetInBitNum();

  for (size_t i = 0; i < range; i++) {
    DpfOutStore temp0 = context.Eval(k0, i);
    DpfOutStore temp1 = context.Eval(k1, i);
    DpfOutStore result = context.TruncateSs(temp0 + temp1);
    if (i == params.alpha) {
      EXPECT_EQ(result, params.beta);
    } else {
      EXPECT_EQ(result, 0);
    }
  }

  DpfKey k1_copy;
  auto k1_string = k1.Serialize();
  k1_copy.Deserialize(k1_string);

  for (size_t i = 0; i < range; i++) {
    DpfOutStore temp0 = context.Eval(k0, i);
    DpfOutStore temp1 = context.Eval(k1_copy, i);
    DpfOutStore result = context.TruncateSs(temp0 + temp1);
    if (i == params.alpha) {
      EXPECT_EQ(result, params.beta);
    } else {
      EXPECT_EQ(result, 0);
    }
  }
}

TEST_P(FssDpfEvalAllTest, Works) {
  auto params = GetParam();
  DpfKey k0;
  DpfKey k1;
  DpfContext context;
  uint128_t first_mk = 0;
  uint128_t second_mk = 1;

  context.SetInBitNum(params.InBitnum);
  context.SetSsBitNum(params.SsBitnum);

  std::tie(k0, k1) =
      context.Gen(params.alpha, params.beta, first_mk, second_mk, true);

  // k0.Print();
  // k1.Print();

  std::vector<DpfOutStore> temp0 = context.EvalAll(k0);
  std::vector<DpfOutStore> temp1 = context.EvalAll(k1);

  size_t range = 1 << context.GetInBitNum();

  for (size_t i = 0; i < range; i++) {
    DpfOutStore result = context.TruncateSs(temp0.at(i) + temp1.at(i));

    if (i == params.alpha) {
      EXPECT_EQ(result, params.beta);
    } else {
      EXPECT_EQ(result, 0);
    }
  }

  DpfKey k1_copy;
  auto k1_string = k1.Serialize();
  k1_copy.Deserialize(k1_string);

  temp0 = context.EvalAll(k0);
  temp1 = context.EvalAll(k1_copy);

  for (size_t i = 0; i < range; i++) {
    DpfOutStore result = context.TruncateSs(temp0.at(i) + temp1.at(i));

    if (i == params.alpha) {
      EXPECT_EQ(result, params.beta);
    } else {
      EXPECT_EQ(result, 0);
    }
  }
}

INSTANTIATE_TEST_SUITE_P(Works_Instances, FssDpfGenTest,
                         testing::Values(TestParams{1, 1, 2, 1},   //
                                         TestParams{1, 2, 2, 4},   //
                                         TestParams{1, 2, 2, 8},   //
                                         TestParams{3, 5, 4, 16},  //
                                         TestParams{1, 2, 4, 32},  //
                                         TestParams{1, 2, 8, 64}));

INSTANTIATE_TEST_SUITE_P(Works_Instances, FssDpfEvalTest,
                         testing::Values(TestParams{1, 1, 2, 1},   //
                                         TestParams{1, 2, 2, 4},   //
                                         TestParams{1, 2, 2, 8},   //
                                         TestParams{3, 5, 4, 16},  //
                                         TestParams{1, 2, 4, 32},  //
                                         TestParams{1, 2, 8, 64}));

INSTANTIATE_TEST_SUITE_P(Works_Instances, FssDpfEvalAllTest,
                         testing::Values(TestParams{1, 1, 2, 1},   //
                                         TestParams{1, 1, 4, 1},   //
                                         TestParams{1, 1, 6, 1},   //
                                         TestParams{1, 1, 8, 1},   //
                                         TestParams{1, 2, 10, 4},  //
                                         TestParams{1, 2, 12, 8},  //
                                         TestParams{3, 5, 14, 16}));

}  // namespace yacl::crypto
