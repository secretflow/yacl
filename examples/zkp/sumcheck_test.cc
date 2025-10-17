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

#include "zkp/sumcheck.h"

#include "gtest/gtest.h"

namespace examples::zkp {

class SumcheckTest : public ::testing::Test {
  protected:
  void SetUp() override {
    modulus_p_ = yacl::math::MPInt("103");

    // g(x_1, x_2) = x_1 + 2*x_2
    polynomial_g_ = {yacl::math::MPInt(0), 
                     yacl::math::MPInt(2),
                     yacl::math::MPInt(1), 
                     yacl::math::MPInt(3)};

    // H = g(0,0) + g(0,1) + g(1,0) + g(1,1) = 0 + 2 + 1 + 3 = 6
    correct_sum_h_ = yacl::math::MPInt(6);
  }
  yacl::math::MPInt modulus_p_;
  MultiLinearPolynomial polynomial_g_;
  yacl::math::MPInt correct_sum_h_;
};

TEST_F(SumcheckTest, HonestProver) {
  bool success = RunSumcheckProtocol(polynomial_g_, correct_sum_h_, modulus_p_);
  EXPECT_TRUE(success);
}

TEST_F(SumcheckTest, FraudProver) {
  yacl::math::MPInt fraudulent_sum_h(10);
  bool success = RunSumcheckProtocol(polynomial_g_, fraudulent_sum_h, modulus_p_);
  EXPECT_FALSE(success);
}

}  // namespace examples::zkp