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

#include "yacl/crypto/experimental/zkp/sumcheck/sumcheck.h"

#include "gtest/gtest.h"
#include "yacl/crypto/experimental/zkp/sumcheck/polynomial.h"

namespace examples::zkp {

class SumcheckTest : public ::testing::Test {
 protected:
  // constructor
  SumcheckTest()
      : polynomial_g_({yacl::math::MPInt(0),   // g(0,0) = 0
                       yacl::math::MPInt(2),   // g(0,1) = 2
                       yacl::math::MPInt(1),   // g(1,0) = 1
                       yacl::math::MPInt(3)})  // g(1,1) = 3
  {}

  void SetUp() override {
    modulus_p_ = yacl::math::MPInt("103");
    // H = g(0,0) + g(0,1) + g(1,0) + g(1,1) = 0 + 2 + 1 + 3 = 6
    correct_sum_h_ = yacl::math::MPInt(6);
  }

  yacl::math::MPInt modulus_p_;
  MultilinearPolynomial polynomial_g_;
  yacl::math::MPInt correct_sum_h_;
};

TEST_F(SumcheckTest, HonestProver) {
  bool success = RunSumcheckProtocol(polynomial_g_, correct_sum_h_, modulus_p_);
  EXPECT_TRUE(success);
}

TEST_F(SumcheckTest, FraudProver) {
  yacl::math::MPInt fraudulent_sum_h(10);
  bool success =
      RunSumcheckProtocol(polynomial_g_, fraudulent_sum_h, modulus_p_);
  EXPECT_FALSE(success);
}

class ZeroCheckTest : public ::testing::Test {
 protected:
  void SetUp() override { modulus_p_ = yacl::math::MPInt("103"); }
  yacl::math::MPInt modulus_p_;
};

TEST_F(ZeroCheckTest, HonestProver) {
  MultilinearPolynomial poly_A(
      {FieldElem(0), FieldElem(0), FieldElem(0), FieldElem(0)});
  bool success = RunZeroCheckProtocol(poly_A, modulus_p_);
  EXPECT_TRUE(success);
}

TEST_F(ZeroCheckTest, FraudProver) {
  MultilinearPolynomial poly_A(
      {FieldElem(9), FieldElem(3), FieldElem(6), FieldElem(10)});
  bool success = RunZeroCheckProtocol(poly_A, modulus_p_);
  EXPECT_FALSE(success);
}

class OneCheckTest : public ::testing::Test {
 protected:
  void SetUp() override { modulus_p_ = yacl::math::MPInt("103"); }
  yacl::math::MPInt modulus_p_;
};

TEST_F(OneCheckTest, AllOnesHonestProver) {
  MultilinearPolynomial poly_y(
      {FieldElem(1), FieldElem(1), FieldElem(1), FieldElem(1)});
  bool success = RunOneCheckProtocol(poly_y, modulus_p_);
  EXPECT_TRUE(success);
}

TEST_F(OneCheckTest, NotAllOnesFraudProver) {
  // y(x1, x2) is a bit vector, but not all entries are 1
  MultilinearPolynomial poly_y_fraud(
      {FieldElem(1), FieldElem(0), FieldElem(1), FieldElem(1)});
  bool success = RunOneCheckProtocol(poly_y_fraud, modulus_p_);
  EXPECT_FALSE(success);
}

TEST_F(OneCheckTest, NotABitVectorFraudProver) {
  MultilinearPolynomial poly_y_fraud(
      {FieldElem(1), FieldElem(5), FieldElem(1), FieldElem(1)});
  bool success = RunOneCheckProtocol(poly_y_fraud, modulus_p_);
  EXPECT_FALSE(success);
}

}  // namespace examples::zkp