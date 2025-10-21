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

#include "zkp/sumcheck/sumcheck.h"

#include "yacl/base/exception.h"

namespace examples::zkp {

namespace {

FieldElem EvaluateUnivariate(const UnivariatePolynomial& poly,
                             const FieldElem& x, const FieldElem& modulus) {
  FieldElem result(0);
  FieldElem x_pow(1);

  for (const auto& coeff : poly) {
    FieldElem term;
    FieldElem::MulMod(coeff, x_pow, modulus, &term);
    FieldElem::AddMod(result, term, modulus, &result);
    FieldElem::MulMod(x_pow, x, modulus, &x_pow);
  }
  return result;
}

FieldElem EvaluateMultilinear(const MultiLinearPolynomial& g,
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

FieldElem RandFieldElem(const FieldElem& modulus) {
  const size_t num_bytes = modulus.BitCount();
  auto rand_bytes = yacl::crypto::SecureRandBytes(num_bytes);
  FieldElem rand_val;
  rand_val.FromMagBytes(
      absl::MakeConstSpan(rand_bytes.data(), rand_bytes.size()));
  FieldElem::Mod(rand_val, modulus, &rand_val);
  return rand_val;
}

// Element-wise product of two multilinear polynomials.
MultiLinearPolynomial MultiplyPolynomials(const MultiLinearPolynomial& p1,
                                          const MultiLinearPolynomial& p2,
                                          const FieldElem& modulus) {
  YACL_ENFORCE(p1.size() == p2.size(), "Polynomials must have the same size.");
  MultiLinearPolynomial result(p1.size());
  for (size_t i = 0; i < p1.size(); ++i) {
    FieldElem::MulMod(p1[i], p2[i], modulus, &result[i]);
  }
  return result;
}

// eq(r, x) = \prod_{i=1 to k} (r_i * x_i + (1-r_i)*(1-x_i))
MultiLinearPolynomial BuildEqPolynomial(absl::Span<const FieldElem> r,
                                        const FieldElem& modulus) {
  size_t k = r.size();
  size_t N = 1U << k;
  MultiLinearPolynomial eq_poly_evals(N);
  FieldElem one(1);

  for (size_t i = 0; i < N; ++i) {
    FieldElem res(1);
    for (size_t j = 0; j < k; ++j) {
      // x_j is the j-th bit of i (from MSB)
      bool x_j_is_one = ((i >> (k - 1 - j)) & 1);
      const auto& r_j = r[j];
      FieldElem term;

      if (x_j_is_one) {
        term = r_j;
      } else {
        FieldElem::SubMod(one, r_j, modulus, &term);
      }
      FieldElem::MulMod(res, term, modulus, &res);
    }
    eq_poly_evals[i] = res;
  }
  return eq_poly_evals;
}

// Build the alpha polynomial \hat{α}(i) = α^i.
MultiLinearPolynomial BuildAlphaPolynomial(size_t num_vars,
                                           const FieldElem& alpha,
                                           const FieldElem& modulus) {
  size_t N = 1U << num_vars;
  MultiLinearPolynomial alpha_poly_evals(N);
  FieldElem current_power(1);

  for (size_t i = 0; i < N; ++i) {
    alpha_poly_evals[i] = current_power;
    FieldElem::MulMod(current_power, alpha, modulus, &current_power);
  }
  return alpha_poly_evals;
}

// Compute the sum \sum_{i=0 to N-1} α^i.
FieldElem ComputeAlphaSum(size_t num_vars, const FieldElem& alpha,
                          const FieldElem& modulus) {
  size_t N_val = 1U << num_vars;
  FieldElem N(N_val);
  FieldElem one(1);

  if (alpha == one) {
    return N;
  }

  // Use geometric series formula: (alpha^N - 1) / (alpha - 1)
  FieldElem alpha_pow_N;
  FieldElem::PowMod(alpha, N, modulus, &alpha_pow_N);
  FieldElem numerator;
  FieldElem::SubMod(alpha_pow_N, one, modulus, &numerator);
  FieldElem denominator;
  FieldElem::SubMod(alpha, one, modulus, &denominator);
  FieldElem inv_denominator;
  FieldElem::InvertMod(denominator, modulus, &inv_denominator);
  FieldElem result;
  FieldElem::MulMod(numerator, inv_denominator, modulus, &result);
  return result;
}

}  // namespace

SumcheckProver::SumcheckProver(const MultiLinearPolynomial& polynomial,
                               const FieldElem& modulus)
    : current_g_evals_(polynomial), modulus_p_(modulus) {
  YACL_ENFORCE(polynomial.size() > 0 &&
                   (polynomial.size() & (polynomial.size() - 1)) == 0,
               "Polynomial size must be a power of 2.");
  num_vars_ = std::log2(polynomial.size());
}

UnivariatePolynomial SumcheckProver::ComputeNextRoundPoly() {
  YACL_ENFORCE(current_round_ < num_vars_, "No more rounds to prove.");

  FieldElem p_i_at_0(0);
  FieldElem p_i_at_1(0);
  size_t half_size = current_g_evals_.size() / 2;

  for (size_t j = 0; j < half_size; ++j) {
    FieldElem::AddMod(p_i_at_0, current_g_evals_[j], modulus_p_, &p_i_at_0);
    FieldElem::AddMod(p_i_at_1, current_g_evals_[j + half_size], modulus_p_,
                      &p_i_at_1);
  }

  FieldElem c1;
  FieldElem::SubMod(p_i_at_1, p_i_at_0, modulus_p_, &c1);
  return {p_i_at_0, c1};  // p_i(X) = p_i_at_0 + c1 * X
}

void SumcheckProver::ProcessChallenge(const FieldElem& challenge) {
  size_t half_size = current_g_evals_.size() / 2;
  std::vector<FieldElem> next_g_evals;
  next_g_evals.reserve(half_size);

  for (size_t j = 0; j < half_size; ++j) {
    const auto& eval_at_0 = current_g_evals_[j];
    const auto& eval_at_1 = current_g_evals_[j + half_size];

    FieldElem one(1);
    FieldElem one_minus_ri;
    FieldElem::SubMod(one, challenge, modulus_p_, &one_minus_ri);

    FieldElem term1, term2, new_eval;
    FieldElem::MulMod(eval_at_0, one_minus_ri, modulus_p_, &term1);
    FieldElem::MulMod(eval_at_1, challenge, modulus_p_, &term2);
    FieldElem::AddMod(term1, term2, modulus_p_, &new_eval);
    next_g_evals.push_back(new_eval);
  }
  current_g_evals_ = std::move(next_g_evals);
  current_round_++;
}

FieldElem SumcheckProver::GetFinalEvaluation() const {
  YACL_ENFORCE(current_round_ == num_vars_ && current_g_evals_.size() == 1,
               "Protocol hasn't finished yet.");
  return current_g_evals_[0];
}

SumcheckVerifier::SumcheckVerifier(const FieldElem& claimed_sum,
                                   size_t num_vars, const FieldElem& modulus)
    : expected_sum_(claimed_sum), num_vars_(num_vars), modulus_p_(modulus) {
  challenges_.reserve(num_vars_);
}

std::optional<FieldElem> SumcheckVerifier::VerifyRound(
    const UnivariatePolynomial& round_poly) {
  YACL_ENFORCE(current_round_ < num_vars_, "No more rounds to verify.");
  if (round_poly.size() != 2) return std::nullopt;

  const FieldElem& a0 = round_poly[0];
  const FieldElem& a1 = round_poly[1];
  FieldElem p_i_at_0 = a0;
  FieldElem p_i_at_1;
  FieldElem::AddMod(a0, a1, modulus_p_, &p_i_at_1);

  FieldElem sum_check;
  FieldElem::AddMod(p_i_at_0, p_i_at_1, modulus_p_, &sum_check);

  if (sum_check != expected_sum_) {
    return std::nullopt;
  }
  FieldElem challenge = RandFieldElem(modulus_p_);
  challenges_.push_back(challenge);
  expected_sum_ = EvaluateUnivariate(round_poly, challenge, modulus_p_);
  current_round_++;
  return challenge;
}

bool SumcheckVerifier::FinalCheck(const MultiLinearPolynomial& g,
                                  const FieldElem& final_eval_from_prover) {
  if (current_round_ != num_vars_) {
    return false;
  }
  FieldElem final_eval_check = EvaluateMultilinear(g, challenges_, modulus_p_);

  return final_eval_check == final_eval_from_prover &&
         expected_sum_ == final_eval_from_prover;
}

bool RunSumcheckProtocol(const MultiLinearPolynomial& polynomial,
                         const FieldElem& claimed_sum,
                         const FieldElem& modulus) {
  size_t num_vars = std::log2(polynomial.size());

  SumcheckProver prover(polynomial, modulus);
  SumcheckVerifier verifier(claimed_sum, num_vars, modulus);

  for (size_t i = 0; i < num_vars; ++i) {
    UnivariatePolynomial p_i = prover.ComputeNextRoundPoly();
    std::optional<FieldElem> challenge = verifier.VerifyRound(p_i);
    if (!challenge.has_value()) {
      return false;
    }
    prover.ProcessChallenge(challenge.value());
  }

  FieldElem final_eval = prover.GetFinalEvaluation();
  return verifier.FinalCheck(polynomial, final_eval);
}

bool RunZeroCheckProtocol(const MultiLinearPolynomial& poly_A,
                          const FieldElem& modulus) {
  YACL_ENFORCE(poly_A.size() > 0 && (poly_A.size() & (poly_A.size() - 1)) == 0,
               "Polynomial size must be a power of 2.");
  size_t num_vars = std::log2(poly_A.size());

  std::vector<FieldElem> r_eq;  // random challenges
  r_eq.reserve(num_vars);
  for (size_t i = 0; i < num_vars; ++i) {
    r_eq.push_back(RandFieldElem(modulus));
  }

  MultiLinearPolynomial eq_poly =
      BuildEqPolynomial(r_eq, modulus);  // g(X) = A(X) * eq(r_eq, X)
  MultiLinearPolynomial g_poly = MultiplyPolynomials(poly_A, eq_poly, modulus);
  FieldElem claimed_sum_c(0);  // \sum_{x \in {0,1}^k} g(x) = A(r)
  return RunSumcheckProtocol(g_poly, claimed_sum_c, modulus);
}

bool RunOneCheckProtocol(const MultiLinearPolynomial& poly_y,
                         const FieldElem& modulus) {
  YACL_ENFORCE(poly_y.size() > 0 && (poly_y.size() & (poly_y.size() - 1)) == 0,
               "Polynomial size must be a power of 2.");
  size_t num_vars = std::log2(poly_y.size());
  FieldElem alpha = RandFieldElem(modulus);  // random challenge
  FieldElem claimed_sum_c = ComputeAlphaSum(num_vars, alpha, modulus);

  // g(X) = y(X) * \hat{α}(X)
  MultiLinearPolynomial alpha_poly =
      BuildAlphaPolynomial(num_vars, alpha, modulus);
  MultiLinearPolynomial g_poly =
      MultiplyPolynomials(poly_y, alpha_poly, modulus);
  return RunSumcheckProtocol(g_poly, claimed_sum_c, modulus);
}

}  // namespace examples::zkp