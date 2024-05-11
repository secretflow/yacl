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

#include "yacl/kernel/code/ea_code.h"

#include <vector>

#include "gtest/gtest.h"

#include "yacl/crypto/rand/rand.h"

namespace yacl::crypto {

struct TestParams {
  unsigned length;
};

class ExAccCodeTest : public ::testing::TestWithParam<TestParams> {};

using GF64 = uint64_t;
using GF128 = uint128_t;

// Test cast for DualEnocde
#define DECLARE_EX_ACC_TEST(type, weight)                               \
  TEST_P(ExAccCodeTest, ExAcc##weight##_##type##_Work) {                \
    /* GIVEN */                                                         \
    uint32_t n = GetParam().length;                                     \
    ExAccCode<weight> acc(n);                                           \
    ExAccCode<weight> dup_acc(n);                                       \
    auto inout0 = RandVec<type>(n * 2);                                 \
    /* copy inout */                                                    \
    auto inout1 = std::vector<type>(inout0.begin(), inout0.end());      \
    auto inout2 = std::vector<type>(inout0.begin(), inout0.end());      \
    /* copy check */                                                    \
    auto check0 = std::vector<type>(n, 0);                              \
    auto check1 = std::vector<type>(check0.begin(), check0.end());      \
    /* WHEN */                                                          \
    acc.DualEncode(absl::MakeSpan(inout0), absl::MakeSpan(check0));     \
    dup_acc.DualEncode(absl::MakeSpan(inout1), absl::MakeSpan(check1)); \
    inout0 = std::vector<type>(n, 0);                                   \
    /* [Warning] DualEncode for ExAccCode would change input */         \
    acc.DualEncode(absl::MakeSpan(inout2), absl::MakeSpan(inout0));     \
    /* THEN */                                                          \
    uint32_t zero_counter = 0;                                          \
    for (uint32_t i = 0; i < n; ++i) {                                  \
      EXPECT_EQ(inout0[i], check0[i]);                                  \
      EXPECT_EQ(inout0[i], check1[i]);                                  \
      if (inout0[i] == 0) {                                             \
        zero_counter++;                                                 \
      }                                                                 \
    }                                                                   \
    EXPECT_LE(zero_counter, 2);                                         \
  }

// Test cast for DualEnocde2
#define DECLARE_EX_ACC_TEST2(type0, type1, weight)                       \
  TEST_P(ExAccCodeTest, ExAcc##weight##_##type0##x##type1##_Work) {      \
    /* GIVEN */                                                          \
    uint32_t n = GetParam().length;                                      \
    ExAccCode<weight> acc(n);                                            \
    ExAccCode<weight> dup_acc(n);                                        \
    auto inout0 = RandVec<type0>(n * 2);                                 \
    auto inout1 = RandVec<type1>(n * 2);                                 \
    /* copy inout */                                                     \
    auto inout2 = std::vector<type0>(inout0.begin(), inout0.end());      \
    auto inout3 = std::vector<type1>(inout1.begin(), inout1.end());      \
    auto inout4 = std::vector<type0>(inout0.begin(), inout0.end());      \
    auto inout5 = std::vector<type1>(inout1.begin(), inout1.end());      \
    /* copy check */                                                     \
    auto check0 = std::vector<type0>(n, 0);                              \
    auto check1 = std::vector<type1>(n, 0);                              \
    auto check2 = std::vector<type0>(check0.begin(), check0.end());      \
    auto check3 = std::vector<type1>(check1.begin(), check1.end());      \
    /* WHEN */                                                           \
    acc.DualEncode2(absl::MakeSpan(inout0), absl::MakeSpan(check0),      \
                    absl::MakeSpan(inout1), absl::MakeSpan(check1));     \
    dup_acc.DualEncode2(absl::MakeSpan(inout2), absl::MakeSpan(check2),  \
                        absl::MakeSpan(inout3), absl::MakeSpan(check3)); \
    inout0 = std::vector<type0>(n, 0);                                   \
    inout1 = std::vector<type1>(n, 0);                                   \
    /* [Warning] DualEncode for ExAccCode would change input */          \
    acc.DualEncode2(absl::MakeSpan(inout4), absl::MakeSpan(inout0),      \
                    absl::MakeSpan(inout5), absl::MakeSpan(inout1));     \
    /* THEN */                                                           \
    uint32_t zero_counter = 0;                                           \
    for (uint32_t i = 0; i < n; ++i) {                                   \
      EXPECT_EQ(check2[i], check0[i]);                                   \
      EXPECT_EQ(check3[i], check1[i]);                                   \
      EXPECT_EQ(check2[i], inout0[i]);                                   \
      EXPECT_EQ(check3[i], inout1[i]);                                   \
      if (inout0[i] == 0) {                                              \
        zero_counter++;                                                  \
      }                                                                  \
      if (inout1[i] == 0) {                                              \
        zero_counter++;                                                  \
      }                                                                  \
    }                                                                    \
    EXPECT_LE(zero_counter, 4);                                          \
  }

// declare all test cases
#define DECLARE_EX_ACC_TEST_BY_WEIGHT(weight) \
  DECLARE_EX_ACC_TEST(GF64, weight);          \
  DECLARE_EX_ACC_TEST(GF128, weight);         \
  DECLARE_EX_ACC_TEST2(GF64, GF64, weight);   \
  DECLARE_EX_ACC_TEST2(GF64, GF128, weight);  \
  DECLARE_EX_ACC_TEST2(GF128, GF128, weight);

DECLARE_EX_ACC_TEST_BY_WEIGHT(7);
DECLARE_EX_ACC_TEST_BY_WEIGHT(11);
DECLARE_EX_ACC_TEST_BY_WEIGHT(21);
DECLARE_EX_ACC_TEST_BY_WEIGHT(40);

INSTANTIATE_TEST_SUITE_P(Works_Instances, ExAccCodeTest,
                         testing::Values(TestParams{47},     // edge
                                         TestParams{48},     //
                                         TestParams{63},     //
                                         TestParams{64},     //
                                         TestParams{99},     //
                                         TestParams{100},    //
                                         TestParams{101},    //
                                         TestParams{10000},  // ten thousand
                                         TestParams{100000}));

}  // namespace yacl::crypto
