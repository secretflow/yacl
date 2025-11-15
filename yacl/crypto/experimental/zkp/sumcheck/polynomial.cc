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

#include "yacl/crypto/experimental/zkp/sumcheck/polynomial.h"

#include <cmath>

#include "yacl/base/exception.h"
#include "yacl/crypto/rand/rand.h"

namespace examples::zkp {

MultilinearPolynomial::MultilinearPolynomial(MultiLinearPolynomialVec evals)
    : evals_(std::move(evals)) {
  YACL_ENFORCE(evals_.size() > 0 && (evals_.size() & (evals_.size() - 1)) == 0,
               "MultilinearPolynomial size must be a non-zero power of 2.");
  if (evals_.size() == 1) {
    num_vars_ = 0;
  } else {
    num_vars_ = static_cast<size_t>(std::log2(evals_.size()));
  }
}

size_t MultilinearPolynomial::NumVars() const { return num_vars_; }

const MultiLinearPolynomialVec& MultilinearPolynomial::GetEvals() const {
  return evals_;
}

FieldElem MultilinearPolynomial::Evaluate(absl::Span<const FieldElem> r,
                                          const FieldElem& modulus) const {
  YACL_ENFORCE(r.size() == num_vars_,
               "Evaluation point has incorrect number of variables.");
  if (num_vars_ == 0) {
    return evals_[0];
  }

  std::vector<FieldElem> current_evals = evals_;
  const FieldElem kOne(1);

  for (size_t i = 0; i < num_vars_; ++i) {
    const size_t half_size = current_evals.size() / 2;
    const auto& r_i = r[i];

    FieldElem one_minus_ri;
    FieldElem::SubMod(kOne, r_i, modulus, &one_minus_ri);

    for (size_t j = 0; j < half_size; ++j) {
      const auto& eval_at_0 = current_evals[j];
      const auto& eval_at_1 = current_evals[j + half_size];

      // new_eval = eval_at_0 * (1 - r_i) + eval_at_1 * r_i;
      FieldElem term1, term2, new_eval;
      FieldElem::MulMod(eval_at_0, one_minus_ri, modulus, &term1);
      FieldElem::MulMod(eval_at_1, r_i, modulus, &term2);
      FieldElem::AddMod(term1, term2, modulus, &new_eval);

      current_evals[j] = std::move(new_eval);
    }
    current_evals.resize(half_size);
  }
  return current_evals[0];
}

FieldElem RandFieldElem(const FieldElem& modulus) {
  return FieldElem::RandomLtN(modulus);
}

FieldElem SumOverBooleanHypercube(const MultiLinearPolynomialVec& evals,
                                  const FieldElem& modulus) {
  FieldElem total_sum(0);
  for (const auto& val : evals) {
    FieldElem::AddMod(total_sum, val, modulus, &total_sum);
  }
  return total_sum;
}

std::unique_ptr<MultilinearPolynomial> MultiplyPolynomials(
    const MultilinearPolynomial& p1, const MultilinearPolynomial& p2,
    const FieldElem& modulus) {
  const auto& p1_evals = p1.GetEvals();
  const auto& p2_evals = p2.GetEvals();

  YACL_ENFORCE(p1_evals.size() == p2_evals.size(),
               "Polynomials must have the same size.");
  MultiLinearPolynomialVec result_evals(p1_evals.size());
  for (size_t i = 0; i < p1_evals.size(); ++i) {
    FieldElem::MulMod(p1_evals[i], p2_evals[i], modulus, &result_evals[i]);
  }
  return std::make_unique<MultilinearPolynomial>(std::move(result_evals));
}

std::unique_ptr<MultilinearPolynomial> BuildEqPolynomial(
    absl::Span<const FieldElem> r, const FieldElem& modulus) {
  size_t k = r.size();
  size_t N = 1U << k;
  MultiLinearPolynomialVec eq_poly_evals(N);
  const FieldElem kOne(1);

  std::vector<FieldElem> one_minus_r(k);
  for (size_t j = 0; j < k; ++j) {
    FieldElem::SubMod(kOne, r[j], modulus, &one_minus_r[j]);
  }

  for (size_t i = 0; i < N; ++i) {
    FieldElem res(1);
    for (size_t j = 0; j < k; ++j) {
      const FieldElem& term = ((i >> j) & 1) ? r[j] : one_minus_r[j];
      FieldElem::MulMod(res, term, modulus, &res);
    }
    eq_poly_evals[i] = res;
  }
  return std::make_unique<MultilinearPolynomial>(std::move(eq_poly_evals));
}

std::unique_ptr<MultilinearPolynomial> BuildAlphaPolynomial(
    size_t num_vars, const FieldElem& alpha, const FieldElem& modulus) {
  size_t N = 1U << num_vars;
  MultiLinearPolynomialVec alpha_poly_evals(N);
  FieldElem current_power(1);

  for (size_t i = 0; i < N; ++i) {
    alpha_poly_evals[i] = current_power;
    FieldElem::MulMod(current_power, alpha, modulus, &current_power);
  }
  return std::make_unique<MultilinearPolynomial>(std::move(alpha_poly_evals));
}

}  // namespace examples::zkp