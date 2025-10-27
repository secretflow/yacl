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

#include "yacl/crypto/experimental/zkp/logup.h"

#include <cmath>

#include "yacl/crypto/experimental/zkp/polynomial.h"

#include "yacl/base/exception.h"

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
  FieldElem one(1);
  FieldElem zero(0);

  // h_A
  const auto& f_A_evals = f_A_->GetEvals();
  MultiLinearPolynomialVec h_A_evals;
  h_A_evals.reserve(f_A_evals.size());
  for (const auto& f_A_val : f_A_evals) {
    FieldElem denominator;
    FieldElem::SubMod(zeta_, f_A_val, modulus_p_, &denominator);
    YACL_ENFORCE(
        denominator != zero,
        "Division by zero in h_A construction: zeta is a root of f_A.");

    FieldElem inv_denominator;
    FieldElem::InvertMod(denominator, modulus_p_, &inv_denominator);
    h_A_evals.push_back(inv_denominator);
  }
  h_A_ = std::make_shared<MultilinearPolynomial>(std::move(h_A_evals));

  // h_B
  const auto& f_B_evals = f_B_->GetEvals();
  const auto& m_B_evals = m_B_->GetEvals();
  MultiLinearPolynomialVec h_B_evals;
  h_B_evals.reserve(f_B_evals.size());
  for (size_t i = 0; i < f_B_evals.size(); ++i) {
    if (m_B_evals[i] == zero) {
      h_B_evals.push_back(zero);
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
  }
  h_B_ = std::make_shared<MultilinearPolynomial>(std::move(h_B_evals));

  // (q_A(x) = h_A(x) * (zeta - f_A(x)) - 1)
  MultiLinearPolynomialVec q_A_evals;
  q_A_evals.reserve(h_A_->GetEvals().size());
  for (size_t i = 0; i < h_A_->GetEvals().size(); ++i) {
    FieldElem term1, zeta_minus_fA, q_A_val;
    FieldElem::SubMod(zeta_, f_A_evals[i], modulus_p_, &zeta_minus_fA);
    FieldElem::MulMod(h_A_->GetEvals()[i], zeta_minus_fA, modulus_p_, &term1);
    FieldElem::SubMod(term1, one, modulus_p_, &q_A_val);
    q_A_evals.push_back(q_A_val);
  }
  q_A_ = std::make_shared<MultilinearPolynomial>(std::move(q_A_evals));

  // (q_B(y) = h_B(y) * (zeta - f_B(y)) - m_B(y))
  MultiLinearPolynomialVec q_B_evals;
  q_B_evals.reserve(h_B_->GetEvals().size());
  for (size_t i = 0; i < h_B_->GetEvals().size(); ++i) {
    FieldElem term1, zeta_minus_fB, q_B_val;
    FieldElem::SubMod(zeta_, f_B_evals[i], modulus_p_, &zeta_minus_fB);
    FieldElem::MulMod(h_B_->GetEvals()[i], zeta_minus_fB, modulus_p_, &term1);
    FieldElem::SubMod(term1, m_B_evals[i], modulus_p_, &q_B_val);
    q_B_evals.push_back(q_B_val);
  }
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

  auto h_A = prover.Get_h_A();
  if (!RunSumcheckProtocol(*h_A, claimed_sum_A, modulus_p_)) {
    return false;
  }

  auto h_B = prover.Get_h_B();
  if (!RunSumcheckProtocol(*h_B, claimed_sum_B, modulus_p_)) {
    return false;
  }

  auto q_A = prover.Get_q_A();
  if (!RunZeroCheckProtocol(*q_A, modulus_p_)) {
    return false;
  }

  auto q_B = prover.Get_q_B();
  if (!RunZeroCheckProtocol(*q_B, modulus_p_)) {
    return false;
  }

  return true;
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