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

#include "yacl/crypto/experimental/zkp/bulletproofs/r1cs/r1cs_constraint_system.h"
#include "yacl/crypto/experimental/zkp/bulletproofs/generators.h"
#include "yacl/crypto/experimental/zkp/bulletproofs/r1cs/r1cs_proof.h"

namespace examples::zkp {

class RandomizedVerifier;

class R1CSVerifier : public ConstraintSystem {
 public:
  R1CSVerifier(SimpleTranscript* transcript, std::shared_ptr<yacl::crypto::EcGroup> curve_);

  // High-level variable commitments
  Variable Commit(const yacl::crypto::EcPoint& V);

  // ConstraintSystem implementation
  SimpleTranscript* Transcript() override;
  std::tuple<Variable, Variable, Variable> Multiply(LinearCombination left, LinearCombination right) override;
  Result<Variable, R1CSError> Allocate(std::optional<yacl::math::MPInt> assignment) override;
  Result<std::tuple<Variable, Variable, Variable>, R1CSError> AllocateMultiplier(std::optional<std::pair<yacl::math::MPInt, yacl::math::MPInt>> input_assignments) override;
  Metrics GetMetrics() const override;
  void Constrain(LinearCombination lc) override;

  // Randomization API
  using RandomizedCallback = std::function<Result<void, R1CSError>(RandomizedVerifier*)>;
  Result<void, R1CSError> SpecifyRandomizedConstraints(RandomizedCallback callback);

  // Proof verification
  Result<void, R1CSError> Verify(const R1CSProof& proof, const PedersenGens* pc_gens, const BulletproofGens* bp_gens) const;

 private:
  friend class RandomizedVerifier;
  
  // Helper to create randomized constraints
  Result<void, R1CSError> CreateRandomizedConstraints();
  
  // Flattens the constraints into weight vectors, including the constant term
  std::tuple<std::vector<yacl::math::MPInt>, std::vector<yacl::math::MPInt>,
             std::vector<yacl::math::MPInt>, std::vector<yacl::math::MPInt>,
             yacl::math::MPInt>
  FlattenedConstraints(const yacl::math::MPInt& z) const;
  
  SimpleTranscript* transcript_;
  std::shared_ptr<yacl::crypto::EcGroup> curve_;
  
  // Stores the commitments to high-level variables
  std::vector<yacl::crypto::EcPoint> V_;

  // Constraints
  std::vector<LinearCombination> constraints_;
  std::vector<RandomizedCallback> deferred_constraints_;

  // State for allocating low-level variables
  size_t num_vars_ = 0;
  std::optional<size_t> pending_multiplier_;
};


// Wrapper for the verifier in the randomization phase
class RandomizedVerifier {
 public:
  explicit RandomizedVerifier(R1CSVerifier* verifier) : verifier_(verifier) {}

  SimpleTranscript* Transcript() { return verifier_->Transcript(); }
  
  yacl::math::MPInt ChallengeScalar(absl::string_view label);

  std::tuple<Variable, Variable, Variable> Multiply(LinearCombination left, LinearCombination right);
  Result<Variable, R1CSError> Allocate(std::optional<yacl::math::MPInt> assignment);
  void Constrain(LinearCombination lc);

 private:
  R1CSVerifier* verifier_;
};

} // namespace examples::zkp