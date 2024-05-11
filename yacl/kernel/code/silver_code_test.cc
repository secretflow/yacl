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

#include "yacl/kernel/code/silver_code.h"

#include <vector>

#include "gtest/gtest.h"

#include "yacl/base/int128.h"
#include "yacl/crypto/rand/rand.h"

namespace yacl::crypto {

struct TestParams {
  unsigned length;
};

class SilverCodeTest : public ::testing::TestWithParam<TestParams> {};

using GF64 = uint64_t;
using GF128 = uint128_t;

// Test case for DualEncode && DualEncodeInplace
#define DECLARE_SILVER_CODE_TEST(type, weight)                     \
  TEST_P(SilverCodeTest, Silver##weight##_##type##_Works) {        \
    /* GIVEN  */                                                   \
    uint32_t n = GetParam().length;                                \
    SilverCode slv(n, weight);                                     \
    SilverCode dup_slv(n, weight);                                 \
    auto inout = RandVec<type>(n * 2);                             \
    auto check = inout;                                            \
    auto check1 = std::vector<type>(n);                            \
    /* WHEN */                                                     \
    slv.DualEncodeInplace(absl::MakeSpan(inout));                  \
    slv.DualEncode(absl::MakeSpan(check), absl::MakeSpan(check1)); \
    dup_slv.DualEncodeInplace(absl::MakeSpan(check));              \
    /* THEN */                                                     \
    uint32_t zero_counter = 0;                                     \
    for (uint32_t i = 0; i < n; ++i) {                             \
      EXPECT_EQ(inout[i], check[i]);                               \
      EXPECT_EQ(inout[i], check1[i]);                              \
      if (inout[i] == 0) {                                         \
        zero_counter++;                                            \
      }                                                            \
    }                                                              \
    EXPECT_LE(zero_counter, 2);                                    \
  }

// Test case for DualEncode2 && DualEncodeInplace2
#define DECLARE_SILVER_CODE_TEST2(type0, type1, weight)                     \
  TEST_P(SilverCodeTest, Silver##weight##_##type0##x##type1##_Works) {      \
    /* GIVEN  */                                                            \
    uint32_t n = GetParam().length;                                         \
    SilverCode slv(n, weight);                                              \
    SilverCode dup_slv(n, weight);                                          \
    auto inout0 = RandVec<type0>(n * 2);                                    \
    auto inout1 = RandVec<type1>(n * 2);                                    \
    auto check0 = inout0;                                                   \
    auto check1 = inout1;                                                   \
    auto check2 = std::vector<type0>(n);                                    \
    auto check3 = std::vector<type1>(n);                                    \
    /* WHEN */                                                              \
    slv.DualEncodeInplace2(absl::MakeSpan(inout0), absl::MakeSpan(inout1)); \
    slv.DualEncode2(absl::MakeSpan(check0), absl::MakeSpan(check2),         \
                    absl::MakeSpan(check1), absl::MakeSpan(check3));        \
    slv.DualEncodeInplace2(absl::MakeSpan(check0), absl::MakeSpan(check1)); \
    /* THEN */                                                              \
    uint32_t zero_counter = 0;                                              \
    for (uint32_t i = 0; i < n; ++i) {                                      \
      EXPECT_EQ(inout0[i], check0[i]);                                      \
      EXPECT_EQ(inout1[i], check1[i]);                                      \
      EXPECT_EQ(inout0[i], check2[i]);                                      \
      EXPECT_EQ(inout1[i], check3[i]);                                      \
      if (inout0[i] == 0) {                                                 \
        zero_counter++;                                                     \
      }                                                                     \
      if (inout1[i] == 0) {                                                 \
        zero_counter++;                                                     \
      }                                                                     \
    }                                                                       \
    EXPECT_LE(zero_counter, 4);                                             \
  }

// declare all test cases
#define DECLARE_SILVER_TEST_BY_WEIGHT(weight)     \
  DECLARE_SILVER_CODE_TEST(GF64, weight);         \
  DECLARE_SILVER_CODE_TEST2(GF64, GF64, weight);  \
  DECLARE_SILVER_CODE_TEST2(GF64, GF128, weight); \
  DECLARE_SILVER_CODE_TEST2(GF128, GF128, weight);

DECLARE_SILVER_TEST_BY_WEIGHT(5);
DECLARE_SILVER_TEST_BY_WEIGHT(11);

INSTANTIATE_TEST_SUITE_P(Works_Instances, SilverCodeTest,
                         testing::Values(TestParams{11},    // edge
                                         TestParams{47},    //
                                         TestParams{48},    //
                                         TestParams{63},    //
                                         TestParams{64},    //
                                         TestParams{99},    //
                                         TestParams{100},   //
                                         TestParams{101},   //
                                         TestParams{10000}  // ten thousand
                                         //  TestParams{1000000}  // one million
                                         ));

}  // namespace yacl::crypto
