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

#include "zkp/sumcheck/matmul_check.h"

#include <cmath>
#include <numeric>

#include "gtest/gtest.h"

#include "yacl/base/exception.h"

namespace examples::zkp {

FieldElem EvaluateMultilinearTest(const std::vector<FieldElem>& g,
                                  absl::Span<const FieldElem> r,
                                  const FieldElem& modulus) {
  size_t num_vars = r.size();
  YACL_ENFORCE(g.size() == (1U << num_vars),
               "Polynomial evaluation size mismatch number of variables");

  std::vector<FieldElem> evals = g;
  for (size_t i = 0; i < num_vars; ++i) {
    std::vector<FieldElem> next_evals;
    size_t current_size = evals.size() / 2;
    next_evals.reserve(current_size);
    const auto& r_i = r[i];

    for (size_t j = 0; j < current_size; ++j) {
      const auto& eval_at_0 = evals[j];
      const auto& eval_at_1 = evals[j + current_size];

      FieldElem one(1);
      FieldElem one_minus_ri;
      FieldElem::SubMod(one, r_i, modulus, &one_minus_ri);

      FieldElem term1, term2, new_eval;
      FieldElem::MulMod(eval_at_0, one_minus_ri, modulus, &term1);
      FieldElem::MulMod(eval_at_1, r_i, modulus, &term2);
      FieldElem::AddMod(term1, term2, modulus, &new_eval);
      next_evals.push_back(new_eval);
    }
    evals = std::move(next_evals);
  }
  return evals[0];
}

class DenseMultilinearPolynomial : public MultivariatePolynomial {
 public:
  DenseMultilinearPolynomial(std::vector<FieldElem> evaluations,
                             FieldElem modulus)
      : evaluations_(std::move(evaluations)), modulus_(std::move(modulus)) {
    YACL_ENFORCE(evaluations_.size() > 0 &&
                     (evaluations_.size() & (evaluations_.size() - 1)) == 0,
                 "Polynomial size must be a power of 2.");
    num_vars_ = log2(evaluations_.size());
  }

  FieldElem evaluate(const std::vector<FieldElem>& point) const override {
    YACL_ENFORCE(point.size() == num_vars_,
                 "Evaluation point has incorrect number of variables.");
    return EvaluateMultilinearTest(evaluations_, absl::MakeConstSpan(point),
                                   modulus_);
  }

  size_t get_num_variables() const override { return num_vars_; }

 private:
  std::vector<FieldElem> evaluations_;
  size_t num_vars_;
  FieldElem modulus_;
};

class MatmulCheckTest : public ::testing::Test {
 protected:
  void SetUp() override { modulus_p_ = yacl::math::MPInt("103"); }
  yacl::math::MPInt modulus_p_;
};

TEST_F(MatmulCheckTest, MatVecMultiplication) {
  // Matrix M
  auto M = std::make_shared<DenseMultilinearPolynomial>(
      std::vector<FieldElem>{FieldElem(1), FieldElem(2), FieldElem(3),
                             FieldElem(4)},
      modulus_p_);
  auto t = std::make_shared<DenseMultilinearPolynomial>(
      std::vector<FieldElem>{FieldElem(5), FieldElem(6)}, modulus_p_);
  auto a = std::make_shared<DenseMultilinearPolynomial>(
      std::vector<FieldElem>{FieldElem(17), FieldElem(39)}, modulus_p_);
  std::vector<FieldElem> r = {FieldElem(10)};  // Random challenge

  FieldElem expected = a->evaluate(r);
  FieldElem actual = mat_vec_multiplication(M, t, r, modulus_p_);
  EXPECT_EQ(expected, actual);
}

TEST_F(MatmulCheckTest, MatMatMultiplication) {
  auto A = std::make_shared<DenseMultilinearPolynomial>(
      std::vector<FieldElem>{FieldElem(1), FieldElem(2), FieldElem(3),
                             FieldElem(4)},
      modulus_p_);
  auto B = std::make_shared<DenseMultilinearPolynomial>(
      std::vector<FieldElem>{FieldElem(5), FieldElem(6), FieldElem(7),
                             FieldElem(8)},
      modulus_p_);
  auto C = std::make_shared<DenseMultilinearPolynomial>(
      std::vector<FieldElem>{FieldElem(19), FieldElem(22), FieldElem(43),
                             FieldElem(50)},
      modulus_p_);  // Result C = A * B

  // Random challenges
  std::vector<FieldElem> u = {FieldElem(10)};  // for rows of A
  std::vector<FieldElem> v = {FieldElem(20)};  // for columns of B

  std::vector<FieldElem> uv_point = u;
  uv_point.insert(uv_point.end(), v.begin(), v.end());
  FieldElem expected = C->evaluate(uv_point);
  FieldElem actual = mat_mat_multiplication(A, B, u, v, modulus_p_);
  EXPECT_EQ(expected, actual);
}

}  // namespace examples::zkp