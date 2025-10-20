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

#pragma once

#include <memory>

#include <vector>

#include <string>

#include <optional>

#include "yacl/math/mpint/mp_int.h"

#include "yacl/crypto/rand/rand.h"

#include "zkp/sumcheck/sumcheck.h"

namespace examples::zkp {

using yacl::math::MPInt;
using FieldElem = MPInt;
using MultiLinearPolynomialVec = std::vector<FieldElem>;
using UnivariatePolynomial = std::vector<FieldElem>;

class MultilinearPolynomial {
public:
    explicit MultilinearPolynomial(MultiLinearPolynomialVec evals);
    FieldElem Evaluate(const std::vector<FieldElem>& r, const FieldElem& modulus) const;
    size_t NumVars() const;
    const MultiLinearPolynomialVec& GetEvals() const;

private:
    MultiLinearPolynomialVec evals_; // {0,1}^k
    size_t num_vars_;
};

class LogUpProver {
public:
    LogUpProver(std::shared_ptr<const MultilinearPolynomial> f_A,
                std::shared_ptr<const MultilinearPolynomial> f_B,
                std::shared_ptr<const MultilinearPolynomial> m_B,
                const FieldElem& modulus);
    void Setup(const FieldElem& zeta);
    std::pair<FieldElem, FieldElem> GetClaimedSums();
    std::shared_ptr<const MultilinearPolynomial> Get_h_A() const { return h_A_; }
    std::shared_ptr<const MultilinearPolynomial> Get_h_B() const { return h_B_; }
    std::shared_ptr<const MultilinearPolynomial> Get_q_A() const { return q_A_; }
    std::shared_ptr<const MultilinearPolynomial> Get_q_B() const { return q_B_; }

private:
    std::shared_ptr<const MultilinearPolynomial> f_A_;
    std::shared_ptr<const MultilinearPolynomial> f_B_;
    std::shared_ptr<const MultilinearPolynomial> m_B_;
    FieldElem modulus_p_;
    FieldElem zeta_;

    std::shared_ptr<MultilinearPolynomial> h_A_;
    std::shared_ptr<MultilinearPolynomial> h_B_;
    std::shared_ptr<MultilinearPolynomial> q_A_;
    std::shared_ptr<MultilinearPolynomial> q_B_;
};

class LogUpVerifier {
public:
    LogUpVerifier(std::shared_ptr<const MultilinearPolynomial> f_A,
                  std::shared_ptr<const MultilinearPolynomial> f_B,
                  std::shared_ptr<const MultilinearPolynomial> m_B,
                  const FieldElem& modulus);
    bool Verify(LogUpProver& prover);

private:
    std::shared_ptr<const MultilinearPolynomial> f_A_;
    std::shared_ptr<const MultilinearPolynomial> f_B_;
    std::shared_ptr<const MultilinearPolynomial> m_B_;
    FieldElem modulus_p_;
    FieldElem zeta_;
};

bool RunLogUpProtocol(const MultiLinearPolynomialVec& f_A_evals,
                      const MultiLinearPolynomialVec& f_B_evals,
                      const MultiLinearPolynomialVec& m_B_evals,
                      const FieldElem& modulus);

} // namespace examples::zkp