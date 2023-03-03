// Copyright 2023 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "yacl/crypto/base/mpint/montgomery_math.h"

#include "gtest/gtest.h"

namespace yacl::crypto::test {

class MontgomeryMathTest
    : public ::testing::TestWithParam<std::tuple<int64_t, int64_t, int64_t>> {
 protected:
  void SetUp() override {
    // libtommath
    EXPECT_EQ(mp_init_i64(&ta_, std::get<0>(GetParam())), MP_OKAY);
    EXPECT_EQ(mp_init_i64(&tb_, std::get<1>(GetParam())), MP_OKAY);
    EXPECT_EQ(mp_init_i64(&tc_, std::get<2>(GetParam())), MP_OKAY);
    EXPECT_EQ(mp_init(&td_), MP_OKAY);

    // montgomery math
    ma_ = MPInt(static_cast<int64_t>(std::get<0>(GetParam())));
    mb_ = MPInt(static_cast<int64_t>(std::get<1>(GetParam())));
    mc_ = MPInt(static_cast<int64_t>(std::get<2>(GetParam())));
  }

  void TearDown() override { mp_clear_multi(&ta_, &tb_, &tc_, &td_, nullptr); }

  void RunTest(size_t exp_unit_size) {
    MontgomerySpace m_space(mc_);
    BaseTable table;

    m_space.MakeBaseTable(ma_, exp_unit_size, mb_.BitCount(), &table);
    EXPECT_GE(table.exp_max_bits, mb_.BitCount());

    m_space.PowMod(table, mb_, &md_);
    m_space.MapBackToZSpace(&md_);

    // libtommath
    EXPECT_EQ(mp_exptmod(&ta_, &tb_, &tc_, &td_), MP_OKAY);

    // final compare
    EXPECT_EQ(md_.Get<int64_t>(), mp_get_i64(&td_));
  }

 protected:
  mp_int ta_, tb_, tc_, td_;  // td_ = ta_^tb_ mod tc_
  MPInt ma_, mb_, mc_, md_;   // md_ = ma_^mb_ mod mc_
};

// 0 的 0 次方不做测试，数学上未定义
// 格式：底数，指数，模数
// std::make_tuple(1, 0, 1) 的情况 libtommath 有 bug，不做对比
INSTANTIATE_TEST_SUITE_P(
    NormalCase, MontgomeryMathTest,
    testing::Values(
        std::make_tuple(0, 1, 1), std::make_tuple(0, 1, 3),
        std::make_tuple(1, 2, 1), std::make_tuple(1, 1, 1),
        std::make_tuple(1, 0, 3), std::make_tuple(1, 1, 3),
        std::make_tuple(0, 4, 1), std::make_tuple(0, 4, 3),
        std::make_tuple(2, 2, 3), std::make_tuple(2, 3, 3),
        std::make_tuple(3, 2, 3), std::make_tuple(3, 3, 3),
        std::make_tuple(12, 2, 3), std::make_tuple(2, 12, 123),
        std::make_tuple(123, 4, 5), std::make_tuple(4, 123, 12345),
        std::make_tuple(1234, 8, 7), std::make_tuple(8, 1234, 1234567),
        std::make_tuple(12345, 16, 11), std::make_tuple(16, 12345, 1234567),
        std::make_tuple(123456, 32, 13), std::make_tuple(32, 123456, 1234567),
        std::make_tuple(1234567, 64, 12345),
        std::make_tuple(64, 1234567, 1234567),
        std::make_tuple(128, 1234567, 1234567),
        std::make_tuple(257, 1234567, 1234567),
        std::make_tuple(524, 1234567, 1234567),
        std::make_tuple(1077, 1234567, 1234567),
        std::make_tuple(2000, 1234567, 1234567),
        std::make_tuple(43210, 1234567, 1234567),
        std::make_tuple(654321, 1234567, 1234567),
        std::make_tuple(1234567, 1234567, 1234567),
        std::make_tuple(123456789, 123456789, 123456789),
        std::make_tuple(123456789, 123456789, 1),
        std::make_tuple(1234567891011, 1234567891011, 3),
        std::make_tuple(12345678910111213, 12345678910111213, 1),
        std::make_tuple(12345678910111213, 12345678910111213, 3),
        std::make_tuple(12345678910111213, 12345678910111213, 5),
        std::make_tuple(12345678910111213, 12345678910111213,
                        12345678910111213)));

TEST_P(MontgomeryMathTest, TestPowMod) {
  for (size_t i = 1; i < 18; ++i) {
    RunTest(i);
  }
}

TEST_P(MontgomeryMathTest, TestPowModBigNumber) {
  int64_t scale = 987654321987654321LL;

  // libtommath
  mp_int factor;
  ASSERT_EQ(mp_init_i64(&factor, scale), MP_OKAY);
  ASSERT_EQ(mp_mul(&tc_, &factor, &tc_), MP_OKAY);
  ASSERT_EQ(mp_mul(&ta_, &factor, &ta_), MP_OKAY);

  // montgomery math
  MPInt factor2(static_cast<int64_t>(scale));
  MPInt::Mul(mc_, factor2, &mc_);
  MPInt::Mul(ma_, factor2, &ma_);

  for (size_t i = 1; i < 18; ++i) {
    RunTest(i);
  }
  mp_clear(&factor);
}

}  // namespace yacl::crypto::test
