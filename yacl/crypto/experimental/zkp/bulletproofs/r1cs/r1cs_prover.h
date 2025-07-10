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

#include "yacl/crypto/experimental/zkp/bulletproofs/generators.h"
#include "yacl/crypto/experimental/zkp/bulletproofs/r1cs/r1cs_constraint_system.h"
#include "yacl/crypto/experimental/zkp/bulletproofs/r1cs/r1cs_proof.h"

namespace examples::zkp {

class RandomizedProver;

class R1CSProver : public ConstraintSystem {
 public:
  R1CSProver(SimpleTranscript* transcript, const PedersenGens* pc_gens);

  // High-level witness commitments
  std::pair<yacl::crypto::EcPoint, Variable> Commit(
      yacl::math::MPInt v, yacl::math::MPInt v_blinding);

  // ConstraintSystem implementation
  SimpleTranscript* Transcript() override;
  std::tuple<Variable, Variable, Variable> Multiply(
      LinearCombination left, LinearCombination right) override;
  Result<Variable, R1CSError> Allocate(
      std::optional<yacl::math::MPInt> assignment) override;
  Result<std::tuple<Variable, Variable, Variable>, R1CSError>
  AllocateMultiplier(
      std::optional<std::pair<yacl::math::MPInt, yacl::math::MPInt>>
          input_assignments) override;
  Metrics GetMetrics() const override;
  void Constrain(LinearCombination lc) override;

  // Randomization API
  using RandomizedCallback = std::function<Result<void>(RandomizedProver*)>;
  Result<void> SpecifyRandomizedConstraints(RandomizedCallback callback);

  // Proof generation
  Result<R1CSProof, R1CSError> Prove(const BulletproofGens* bp_gens) const;

 private:
  friend class RandomizedProver;

  // Evaluates a linear combination
  yacl::math::MPInt Eval(const LinearCombination& lc) const;

  // Helper to create randomized constraints
  Result<void> CreateRandomizedConstraints();

  // Flattens the constraints into weight vectors
  std::tuple<std::vector<yacl::math::MPInt>, std::vector<yacl::math::MPInt>,
             std::vector<yacl::math::MPInt>, std::vector<yacl::math::MPInt>>
  FlattenedConstraints(const yacl::math::MPInt& z) const;

  SimpleTranscript* transcript_;
  const PedersenGens* pc_gens_;

  // Witness data
  std::vector<yacl::math::MPInt> v_;
  std::vector<yacl::math::MPInt> v_blinding_;
  std::vector<yacl::math::MPInt> a_L_;
  std::vector<yacl::math::MPInt> a_R_;
  std::vector<yacl::math::MPInt> a_O_;

  // Constraints
  std::vector<LinearCombination> constraints_;
  std::vector<RandomizedCallback> deferred_constraints_;

  std::optional<size_t> pending_multiplier_;
};

// Wrapper for the prover in the randomization phase
class RandomizedProver {
 public:
  explicit RandomizedProver(R1CSProver* prover) : prover_(prover) {}

  // Expose a subset of the Prover's API
  SimpleTranscript* Transcript() { return prover_->Transcript(); }

  // RandomizedConstraintSystem API
  yacl::math::MPInt ChallengeScalar(absl::string_view label);

  // Allow adding constraints in the second phase
  std::tuple<Variable, Variable, Variable> Multiply(LinearCombination left,
                                                    LinearCombination right);
  Result<Variable, R1CSError> Allocate(
      std::optional<yacl::math::MPInt> assignment);
  void Constrain(LinearCombination lc);

 private:
  R1CSProver* prover_;
};

}  // namespace examples::zkp