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

#include "yacl/base/exception.h"
#include "yacl/crypto/experimental/zkp/sumcheck/polynomial.h"

namespace examples::zkp {

namespace {

FieldElem EvaluateUnivariate(const UnivariatePolynomial& poly,
                             const FieldElem& x, const FieldElem& modulus) {
  FieldElem result(0);
  for (auto it = poly.rbegin(); it != poly.rend(); ++it) {
    FieldElem::MulMod(result, x, modulus, &result);
    FieldElem::AddMod(result, *it, modulus, &result);
  }
  return result;
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

SumcheckProver::SumcheckProver(const MultilinearPolynomial& polynomial,
                               const FieldElem& modulus)
    : current_g_evals_(polynomial.GetEvals()),
      modulus_p_(modulus),
      num_vars_(polynomial.NumVars()) {}

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

bool SumcheckVerifier::FinalCheck(const MultilinearPolynomial& g,
                                  const FieldElem& final_eval_from_prover) {
  if (current_round_ != num_vars_) {
    return false;
  }
  FieldElem final_eval_check = g.Evaluate(challenges_, modulus_p_);

  return final_eval_check == final_eval_from_prover &&
         expected_sum_ == final_eval_from_prover;
}

bool RunSumcheckProtocol(const MultilinearPolynomial& polynomial,
                         const FieldElem& claimed_sum,
                         const FieldElem& modulus) {
  SumcheckProver prover(polynomial, modulus);
  SumcheckVerifier verifier(claimed_sum, polynomial.NumVars(), modulus);

  for (size_t i = 0; i < polynomial.NumVars(); ++i) {
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

bool RunZeroCheckProtocol(const MultilinearPolynomial& poly_A,
                          const FieldElem& modulus) {
  size_t num_vars = poly_A.NumVars();

  std::vector<FieldElem> r_eq;  // random challenges
  r_eq.reserve(num_vars);
  for (size_t i = 0; i < num_vars; ++i) {
    r_eq.push_back(RandFieldElem(modulus));
  }

  auto eq_poly = BuildEqPolynomial(r_eq, modulus);
  auto g_poly = MultiplyPolynomials(poly_A, *eq_poly, modulus);
  FieldElem claimed_sum_c(0);  // \sum_{x \in {0,1}^k} g(x) = A(r)
  return RunSumcheckProtocol(*g_poly, claimed_sum_c, modulus);
}

bool RunOneCheckProtocol(const MultilinearPolynomial& poly_y,
                         const FieldElem& modulus) {
  size_t num_vars = poly_y.NumVars();
  FieldElem alpha = RandFieldElem(modulus);  // random challenge
  FieldElem claimed_sum_c = ComputeAlphaSum(num_vars, alpha, modulus);

  auto alpha_poly = BuildAlphaPolynomial(num_vars, alpha, modulus);
  auto g_poly = MultiplyPolynomials(poly_y, *alpha_poly, modulus);
  return RunSumcheckProtocol(*g_poly, claimed_sum_c, modulus);
}

}  // namespace examples::zkp