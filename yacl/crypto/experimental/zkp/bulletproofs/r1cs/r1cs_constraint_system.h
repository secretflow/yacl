// Copyright 2025 @yangjucai.
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

#include <functional>

#include "yacl/crypto/experimental/zkp/bulletproofs/r1cs/r1cs_linear_combination.h"
#include "yacl/crypto/experimental/zkp/bulletproofs/r1cs/r1cs_metrics.h"
#include "yacl/crypto/experimental/zkp/bulletproofs/simple_transcript.h"
#include "yacl/crypto/experimental/zkp/bulletproofs/errors.h" 

namespace examples::zkp {

// Forward declarations
class RandomizedProver; 
class RandomizedVerifier;

// The interface for a constraint system, abstracting over the prover
// and verifier's roles.
class ConstraintSystem {
 public:
  virtual ~ConstraintSystem() = default;

  virtual SimpleTranscript* Transcript() = 0;

  virtual std::tuple<Variable, Variable, Variable> Multiply(
      LinearCombination left, LinearCombination right) = 0;

  virtual Result<Variable, R1CSError> Allocate(std::optional<yacl::math::MPInt> assignment) = 0;

  virtual Result<std::tuple<Variable, Variable, Variable>, R1CSError> AllocateMultiplier(
      std::optional<std::pair<yacl::math::MPInt, yacl::math::MPInt>> input_assignments) = 0;

  virtual Metrics GetMetrics() const = 0;

  virtual void Constrain(LinearCombination lc) = 0;
};


} // namespace examples::zkp