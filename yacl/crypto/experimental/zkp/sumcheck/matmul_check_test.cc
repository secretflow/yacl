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

#include "yacl/crypto/experimental/zkp/matmul_check.h"

#include <cmath>
#include <numeric>

#include "gtest/gtest.h"
#include "yacl/crypto/experimental/zkp/polynomial.h"

#include "yacl/base/exception.h"

namespace examples::zkp {

class MatmulCheckTest : public ::testing::Test {
 protected:
  void SetUp() override { modulusP_ = yacl::math::MPInt("103"); }
  yacl::math::MPInt modulusP_;
};

TEST_F(MatmulCheckTest, MatVecMultiplication) {
  // Matrix M, vector t, and result a represented as MultilinearPolynomials
  MultilinearPolynomial M(
      {FieldElem(1), FieldElem(2), FieldElem(3), FieldElem(4)});
  MultilinearPolynomial t({FieldElem(5), FieldElem(6)});
  MultilinearPolynomial a({FieldElem(17), FieldElem(39)});

  std::vector<FieldElem> r = {FieldElem(10)};  // Random challenge

  FieldElem expected = a.Evaluate(r, modulusP_);
  FieldElem actual = MatVecMultiplication(M, t, r, modulusP_);
  EXPECT_EQ(expected, actual);
}

TEST_F(MatmulCheckTest, MatMatMultiplication) {
  MultilinearPolynomial A(
      {FieldElem(1), FieldElem(2), FieldElem(3), FieldElem(4)});
  MultilinearPolynomial B(
      {FieldElem(5), FieldElem(6), FieldElem(7), FieldElem(8)});
  MultilinearPolynomial C(
      {FieldElem(19), FieldElem(22), FieldElem(43), FieldElem(50)});

  // Random challenges
  std::vector<FieldElem> u = {FieldElem(10)};  // for rows of A
  std::vector<FieldElem> v = {FieldElem(20)};  // for columns of B

  std::vector<FieldElem> uvPoint = u;
  uvPoint.insert(uvPoint.end(), v.begin(), v.end());
  FieldElem expected = C.Evaluate(uvPoint, modulusP_);
  FieldElem actual = MatMatMultiplication(A, B, u, v, modulusP_);
  EXPECT_EQ(expected, actual);
}

}  // namespace examples::zkp