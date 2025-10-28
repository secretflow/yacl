// Copyright 2025 Ant Group Co., Ltd.
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

#include "yacl/crypto/experimental/zkp/sumcheck/logup.h"

#include "gtest/gtest.h"

#include "yacl/crypto/experimental/zkp/sumcheck/polynomial.h"

namespace examples::zkp {

class LogUpTest : public ::testing::Test {
 protected:
  void SetUp() override { modulus_p_ = yacl::math::MPInt("257"); }
  yacl::math::MPInt modulus_p_;
};

TEST_F(LogUpTest, HonestProver) {
  MultiLinearPolynomialVec f_A_evals = {FieldElem(5), FieldElem(10)};
  MultiLinearPolynomialVec f_B_evals = {FieldElem(3), FieldElem(5),
                                        FieldElem(10), FieldElem(20)};
  // m_B
  MultiLinearPolynomialVec m_B_evals = {FieldElem(0), FieldElem(1),
                                        FieldElem(1), FieldElem(0)};
  bool success = RunLogUpProtocol(f_A_evals, f_B_evals, m_B_evals, modulus_p_);
  EXPECT_TRUE(success);
}

TEST_F(LogUpTest, HonestProverWithMultiplicity) {
  MultiLinearPolynomialVec f_A_evals = {FieldElem(5), FieldElem(5),
                                        FieldElem(10), FieldElem(10)};
  MultiLinearPolynomialVec f_B_evals = {FieldElem(3), FieldElem(5),
                                        FieldElem(10), FieldElem(20)};

  // m_B
  // f_B[0]=3 -> m_B[0]=0
  // f_B[1]=5 -> m_B[1]=2
  // f_B[2]=10 -> m_B[2]=2
  // f_B[3]=20 -> m_B[3]=0
  MultiLinearPolynomialVec m_B_evals = {FieldElem(0), FieldElem(2),
                                        FieldElem(2), FieldElem(0)};
  bool success = RunLogUpProtocol(f_A_evals, f_B_evals, m_B_evals, modulus_p_);
  EXPECT_TRUE(success);
}

TEST_F(LogUpTest, FraudulentProverSubset) {
  // Use the new type alias MultiLinearPolynomialVec
  MultiLinearPolynomialVec f_A = {FieldElem(5), FieldElem(99)};
  MultiLinearPolynomialVec f_B = {FieldElem(3), FieldElem(5), FieldElem(10),
                                  FieldElem(20)};
  MultiLinearPolynomialVec m_B = {FieldElem(0), FieldElem(1), FieldElem(1),
                                  FieldElem(0)};
  bool success = RunLogUpProtocol(f_A, f_B, m_B, modulus_p_);
  EXPECT_FALSE(success);
}

TEST_F(LogUpTest, FraudulentProverMultiplicity) {
  // Use the new type alias MultiLinearPolynomialVec
  MultiLinearPolynomialVec f_A = {FieldElem(5), FieldElem(5)};
  MultiLinearPolynomialVec f_B = {FieldElem(3), FieldElem(5), FieldElem(10),
                                  FieldElem(20)};
  MultiLinearPolynomialVec m_B = {FieldElem(0), FieldElem(1), FieldElem(1),
                                  FieldElem(0)};

  bool success = RunLogUpProtocol(f_A, f_B, m_B, modulus_p_);
  EXPECT_FALSE(success);
}

}  // namespace examples::zkp