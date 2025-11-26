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

#include "yacl/base/exception.h"
#include "yacl/crypto/experimental/zkp/sumcheck/polynomial.h"

namespace examples::zkp {

LogUpProver::LogUpProver(std::shared_ptr<const MultilinearPolynomial> f_A,
                         std::shared_ptr<const MultilinearPolynomial> f_B,
                         std::shared_ptr<const MultilinearPolynomial> m_B,
                         const FieldElem& modulus)
    : f_A_(std::move(f_A)),
      f_B_(std::move(f_B)),
      m_B_(std::move(m_B)),
      modulus_p_(modulus) {
  YACL_ENFORCE(f_B_->NumVars() == m_B_->NumVars(),
               "f_B and m_B must have the same number of variables.");
}

void LogUpProver::Setup(const FieldElem& zeta) {
  zeta_ = zeta;
  const FieldElem one(1);
  const FieldElem zero(0);

  const size_t num_vars_A = f_A_->NumVars();
  const size_t size_A = 1 << num_vars_A;
  const auto& f_A_evals = f_A_->GetEvals();

  MultiLinearPolynomialVec h_A_evals;
  MultiLinearPolynomialVec q_A_evals;
  h_A_evals.reserve(size_A);
  q_A_evals.reserve(size_A);

  for (size_t i = 0; i < size_A; ++i) {
    FieldElem denominator;
    FieldElem::SubMod(zeta_, f_A_evals[i], modulus_p_, &denominator);
    YACL_ENFORCE(
        denominator != zero,
        "Division by zero in h_A construction: zeta is a root of f_A.");

    FieldElem inv_denominator;
    FieldElem::InvertMod(denominator, modulus_p_, &inv_denominator);
    h_A_evals.push_back(inv_denominator);

    // By definition, q_A(x) = h_A(x) * (zeta - f_A(x)) - 1.
    // Since h_A(x) = 1 / (zeta - f_A(x)), q_A(x) is identically 0.
    q_A_evals.push_back(zero);
  }
  h_A_ = std::make_shared<MultilinearPolynomial>(std::move(h_A_evals));
  q_A_ = std::make_shared<MultilinearPolynomial>(std::move(q_A_evals));

  const size_t num_vars_B = f_B_->NumVars();
  const size_t size_B = 1 << num_vars_B;
  const auto& f_B_evals = f_B_->GetEvals();
  const auto& m_B_evals = m_B_->GetEvals();

  MultiLinearPolynomialVec h_B_evals;
  MultiLinearPolynomialVec q_B_evals;
  h_B_evals.reserve(size_B);
  q_B_evals.reserve(size_B);

  for (size_t i = 0; i < size_B; ++i) {
    if (m_B_evals[i] == zero) {
      h_B_evals.push_back(zero);
      // q_B(y) = 0 * (zeta - f_B(y)) - 0 = 0
      q_B_evals.push_back(zero);
      continue;
    }

    FieldElem denominator;
    FieldElem::SubMod(zeta_, f_B_evals[i], modulus_p_, &denominator);
    YACL_ENFORCE(denominator != zero,
                 "Division by zero in h_B construction: zeta is a root of f_B "
                 "for a non-zero m_B entry.");

    FieldElem inv_denominator;
    FieldElem::InvertMod(denominator, modulus_p_, &inv_denominator);

    FieldElem h_B_val;
    FieldElem::MulMod(m_B_evals[i], inv_denominator, modulus_p_, &h_B_val);
    h_B_evals.push_back(h_B_val);

    // q_B(y) = h_B(y) * (zeta - f_B(y)) - m_B(y)
    FieldElem term1;
    FieldElem::MulMod(h_B_val, denominator, modulus_p_, &term1);
    FieldElem q_B_val;
    FieldElem::SubMod(term1, m_B_evals[i], modulus_p_, &q_B_val);
    q_B_evals.push_back(q_B_val);
  }
  h_B_ = std::make_shared<MultilinearPolynomial>(std::move(h_B_evals));
  q_B_ = std::make_shared<MultilinearPolynomial>(std::move(q_B_evals));
}

std::pair<FieldElem, FieldElem> LogUpProver::GetClaimedSums() {
  YACL_ENFORCE(h_A_ && h_B_, "Prover must be setup before getting sums.");
  FieldElem sum_A = SumOverBooleanHypercube(h_A_->GetEvals(), modulus_p_);
  FieldElem sum_B = SumOverBooleanHypercube(h_B_->GetEvals(), modulus_p_);
  return {sum_A, sum_B};
}

LogUpVerifier::LogUpVerifier(std::shared_ptr<const MultilinearPolynomial> f_A,
                             std::shared_ptr<const MultilinearPolynomial> f_B,
                             std::shared_ptr<const MultilinearPolynomial> m_B,
                             const FieldElem& modulus)
    : f_A_(std::move(f_A)),
      f_B_(std::move(f_B)),
      m_B_(std::move(m_B)),
      modulus_p_(modulus) {}

bool LogUpVerifier::Verify(LogUpProver& prover) {
  zeta_ = RandFieldElem(modulus_p_);
  prover.Setup(zeta_);
  auto [claimed_sum_A, claimed_sum_B] = prover.GetClaimedSums();

  if (claimed_sum_A != claimed_sum_B) {
    return false;
  }

  return RunSumcheckProtocol(*prover.GetHA(), claimed_sum_A, modulus_p_) &&
         RunSumcheckProtocol(*prover.GetHB(), claimed_sum_B, modulus_p_) &&
         RunZeroCheckProtocol(*prover.GetQA(), modulus_p_) &&
         RunZeroCheckProtocol(*prover.GetQB(), modulus_p_);
}

bool RunLogUpProtocol(const MultiLinearPolynomialVec& f_A_evals,
                      const MultiLinearPolynomialVec& f_B_evals,
                      const MultiLinearPolynomialVec& m_B_evals,
                      const FieldElem& modulus) {
  auto f_A = std::make_shared<const MultilinearPolynomial>(f_A_evals);
  auto f_B = std::make_shared<const MultilinearPolynomial>(f_B_evals);
  auto m_B = std::make_shared<const MultilinearPolynomial>(m_B_evals);

  LogUpProver prover(f_A, f_B, m_B, modulus);
  LogUpVerifier verifier(f_A, f_B, m_B, modulus);

  return verifier.Verify(prover);
}

}  // namespace examples::zkp