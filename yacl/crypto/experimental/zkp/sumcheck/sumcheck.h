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
#include <optional>
#include <string>
#include <vector>

#include "zkp/sumcheck/polynomial.h"

namespace examples::zkp {

class SumcheckProver {
 public:
  SumcheckProver(const MultilinearPolynomial& polynomial,
                 const FieldElem& modulus);
  UnivariatePolynomial ComputeNextRoundPoly();
  void ProcessChallenge(const FieldElem& challenge);
  FieldElem GetFinalEvaluation() const;

 private:
  std::vector<FieldElem> current_g_evals_;
  FieldElem modulus_p_;
  size_t num_vars_;
  size_t current_round_ = 0;
};

class SumcheckVerifier {
 public:
  SumcheckVerifier(const FieldElem& claimed_sum, size_t num_vars,
                   const FieldElem& modulus);
  std::optional<FieldElem> VerifyRound(const UnivariatePolynomial& round_poly);
  bool FinalCheck(const MultilinearPolynomial& g,
                  const FieldElem& final_eval_from_prover);

 private:
  FieldElem expected_sum_;
  size_t num_vars_;
  FieldElem modulus_p_;
  size_t current_round_ = 0;
  std::vector<FieldElem> challenges_;
};

bool RunSumcheckProtocol(const MultilinearPolynomial& polynomial,
                         const FieldElem& claimed_sum,
                         const FieldElem& modulus);
bool RunZeroCheckProtocol(const MultilinearPolynomial& poly_A,
                          const FieldElem& modulus);
bool RunOneCheckProtocol(const MultilinearPolynomial& poly_y,
                         const FieldElem& modulus);

}  // namespace examples::zkp