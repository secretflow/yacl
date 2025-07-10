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

#include "gtest/gtest.h"
#include <algorithm>
#include <numeric>
#include <random>
#include <vector>
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/crypto/experimental/zkp/bulletproofs/errors.h"
#include "yacl/crypto/experimental/zkp/bulletproofs/generators.h"
#include "yacl/crypto/experimental/zkp/bulletproofs/r1cs/r1cs_config.h"
#include "yacl/crypto/experimental/zkp/bulletproofs/r1cs/r1cs_constraint_system.h"
#include "yacl/crypto/experimental/zkp/bulletproofs/r1cs/r1cs_linear_combination.h"
#include "yacl/crypto/experimental/zkp/bulletproofs/r1cs/r1cs_proof.h"
#include "yacl/crypto/experimental/zkp/bulletproofs/r1cs/r1cs_prover.h"
#include "yacl/crypto/experimental/zkp/bulletproofs/r1cs/r1cs_verifier.h"
#include "yacl/crypto/experimental/zkp/bulletproofs/util.h"
#include "yacl/crypto/rand/rand.h"

namespace examples::zkp {

class R1CSTest : public ::testing::Test {
 protected:
  void SetUp() override {
    curve_ = yacl::crypto::EcGroupFactory::Instance().Create(
        kR1CSProofEcName, yacl::ArgLib = kR1CSProofEcLib);
    pc_gens_ = std::make_shared<PedersenGens>(curve_);
  }

  
  // --------------------------------------------------------------------------
  // Gadget 1: Shuffle Proof
  // --------------------------------------------------------------------------
  struct ShuffleProof {
    R1CSProof proof;
    ShuffleProof() = default;
    explicit ShuffleProof(R1CSProof p) : proof(std::move(p)) {}
  };

  Result<void, R1CSError> ShuffleGadget(ConstraintSystem* cs,
                                         const std::vector<Variable>& x,
                                         const std::vector<Variable>& y) {
    YACL_ENFORCE(x.size() == y.size());
    size_t k = x.size();

    if (k < 2) {
      if (k == 1) {
        cs->Constrain(LinearCombination(y[0]) - x[0]);
      }
      return Result<void, R1CSError>::Ok();
    }

    auto* prover = dynamic_cast<R1CSProver*>(cs);
    auto* verifier = dynamic_cast<R1CSVerifier*>(cs);

    if (prover) {
      R1CSProver::RandomizedCallback callback =
          [k, &x, &y](RandomizedProver* rcs) -> Result<void> { 
        yacl::math::MPInt z = rcs->ChallengeScalar("shuffle challenge");
        auto compute_product =
            [&](const std::vector<Variable>& vars) -> LinearCombination {
          auto [_, __, product] = rcs->Multiply(
              LinearCombination(vars[k - 1]) - z,
              LinearCombination(vars[k - 2]) - z);
          for (int i = k - 3; i >= 0; --i) {
            auto [___, ____, next_product] = rcs->Multiply(
                LinearCombination(product), LinearCombination(vars[i]) - z);
            product = next_product;
          }
          return product;
        };
        rcs->Constrain(compute_product(x) - compute_product(y));
        return Result<void>::Ok();
      };    
      auto res = prover->SpecifyRandomizedConstraints(callback);
      if (res.IsErr()) {
        // Convert the ProofError into an R1CSError for the gadget's return type
        return Result<void, R1CSError>::Err(R1CSError(res.Error()));
      }
      return Result<void, R1CSError>::Ok();
    }

    if (verifier) {
      R1CSVerifier::RandomizedCallback callback =
          [k, &x, &y](RandomizedVerifier* rcs) -> Result<void, R1CSError> {
        yacl::math::MPInt z = rcs->ChallengeScalar("shuffle challenge");
        auto compute_product =
            [&](const std::vector<Variable>& vars) -> LinearCombination {
          auto [_, __, product] = rcs->Multiply(
              LinearCombination(vars[k - 1]) - z,
              LinearCombination(vars[k - 2]) - z);
          for (int i = k - 3; i >= 0; --i) {
            auto [___, ____, next_product] = rcs->Multiply(
                LinearCombination(product), LinearCombination(vars[i]) - z);
            product = next_product;
          }
          return product;
        };
        rcs->Constrain(compute_product(x) - compute_product(y));
        return Result<void, R1CSError>::Ok();
      };
      auto res = verifier->SpecifyRandomizedConstraints(callback);
      if (res.IsErr()) {
        return Result<void, R1CSError>::Err(R1CSError(res.Error()));
      }
      return Result<void, R1CSError>::Ok();
    }

    YACL_THROW("ConstraintSystem is neither a Prover nor a Verifier");
  }

  void ShuffleTestHelper(size_t k) {
    auto bp_gens =
        std::make_shared<BulletproofGens>(curve_, NextPowerOfTwo(2 * k), 1);
    ShuffleProof proof;
    std::vector<yacl::crypto::EcPoint> input_commitments, output_commitments;

    {
      SimpleTranscript prover_transcript("ShuffleProofTest");
      prover_transcript.AppendMessage("dom-sep", "ShuffleProof");
      prover_transcript.AppendMessage("k", std::to_string(k));
      R1CSProver prover(&prover_transcript, pc_gens_.get());
      std::vector<yacl::math::MPInt> input_values;
      std::vector<Variable> input_vars;
      input_values.reserve(k);
      input_vars.reserve(k);

      for (size_t i = 0; i < k; ++i) {
        auto val = CreateDummyScalar(curve_);
        auto [commit, var] = prover.Commit(val, CreateDummyScalar(curve_));
        input_values.push_back(val);
        input_commitments.push_back(commit);
        input_vars.push_back(var);
      }
      std::vector<yacl::math::MPInt> output_values = input_values;
      std::shuffle(output_values.begin(), output_values.end(),
                   std::mt19937(std::random_device()()));
      std::vector<Variable> output_vars;
      output_vars.reserve(k);
      for (size_t i = 0; i < k; ++i) {
        auto [commit, var] =
            prover.Commit(output_values[i], CreateDummyScalar(curve_));
        output_commitments.push_back(commit);
        output_vars.push_back(var);
      }
      ASSERT_TRUE(ShuffleGadget(&prover, input_vars, output_vars).IsOk());
      auto proof_res = prover.Prove(bp_gens.get());
      ASSERT_TRUE(proof_res.IsOk()) << proof_res.Error().what();
      proof = ShuffleProof(std::move(proof_res).TakeValue());
    }
    
    {
      SimpleTranscript verifier_transcript("ShuffleProofTest");
      verifier_transcript.AppendMessage("dom-sep", "ShuffleProof");
      verifier_transcript.AppendMessage("k", std::to_string(k));
      R1CSVerifier verifier(&verifier_transcript, curve_);
      std::vector<Variable> input_vars, output_vars;
      for (const auto& c : input_commitments)
        input_vars.push_back(verifier.Commit(c));


      for (const auto& c : output_commitments)
        output_vars.push_back(verifier.Commit(c));

      ASSERT_TRUE(ShuffleGadget(&verifier, input_vars, output_vars).IsOk());
      
      auto verify_res =
          verifier.Verify(proof.proof, pc_gens_.get(), bp_gens.get());
      ASSERT_TRUE(verify_res.IsOk()) << verify_res.Error().what();
    }
  }

  // --------------------------------------------------------------------------
  // Gadget 2: Example Gadget
  // --------------------------------------------------------------------------
  void ExampleGadget(ConstraintSystem* cs, LinearCombination a1,
                     LinearCombination a2, LinearCombination b1,
                     LinearCombination b2, LinearCombination c1,
                     LinearCombination c2) {
    auto [_, __, c_var] = cs->Multiply(a1 + a2, b1 + b2);
    cs->Constrain(c1 + c2 - c_var);
  }

  Result<void, R1CSError> ExampleGadgetRoundtripHelper(
      uint64_t a1, uint64_t a2, uint64_t b1, uint64_t b2, uint64_t c1,
      uint64_t c2) {
    auto bp_gens = std::make_shared<BulletproofGens>(curve_, 128, 1);
    R1CSProof proof;
    std::vector<yacl::crypto::EcPoint> commitments;
    {
      SimpleTranscript prover_transcript("R1CSExampleGadget");
      R1CSProver prover(&prover_transcript, pc_gens_.get());
      std::vector<Variable> vars;
      for (uint64_t val : {a1, a2, b1, b2, c1}) {
        auto [com, var] =
            prover.Commit(yacl::math::MPInt(val), CreateDummyScalar(curve_));
        commitments.push_back(com);
        vars.push_back(var);
      }
      ExampleGadget(&prover, vars[0], vars[1], vars[2], vars[3], vars[4],
                    yacl::math::MPInt(c2));
      auto proof_res = prover.Prove(bp_gens.get());
      if (proof_res.IsErr()) {
        return Result<void, R1CSError>::Err(proof_res.Error());
      }
      proof = std::move(proof_res).TakeValue();
    }
    {
      SimpleTranscript verifier_transcript("R1CSExampleGadget");
      R1CSVerifier verifier(&verifier_transcript, curve_);
      std::vector<Variable> vars;
      for (const auto& c : commitments) vars.push_back(verifier.Commit(c));
      ExampleGadget(&verifier, vars[0], vars[1], vars[2], vars[3], vars[4],
                    yacl::math::MPInt(c2));
      return verifier.Verify(proof, pc_gens_.get(), bp_gens.get());
    }
  }

  // --------------------------------------------------------------------------
  // Gadget 3: Range Proof
  // --------------------------------------------------------------------------
  Result<void, R1CSError> RangeProofGadget(
      ConstraintSystem* cs, LinearCombination v,
      std::optional<uint64_t> v_assignment, size_t n) {
    yacl::math::MPInt exp_2(1);
    for (size_t i = 0; i < n; ++i) {
      std::optional<std::pair<yacl::math::MPInt, yacl::math::MPInt>> assignment;
      if (v_assignment.has_value()) {
        uint64_t bit = (*v_assignment >> i) & 1;
        assignment = {{yacl::math::MPInt(1 - bit), yacl::math::MPInt(bit)}};
      }
      auto res = cs->AllocateMultiplier(assignment);
      YACL_ENFORCE(res.IsOk());
      auto [a, b, o] = std::move(res).TakeValue();
      cs->Constrain(LinearCombination(o));
      cs->Constrain(LinearCombination(a) + b - yacl::math::MPInt(1));
      v -= LinearCombination(b) * exp_2;
      exp_2 *= 2;
    }
    cs->Constrain(v);
    return Result<void, R1CSError>::Ok();
  }

  Result<void, R1CSError> RangeProofHelper(uint64_t v_val, size_t n) {
    auto bp_gens = std::make_shared<BulletproofGens>(curve_, 128, 1);
    R1CSProof proof;
    yacl::crypto::EcPoint commitment;
    {
      SimpleTranscript prover_transcript("RangeProofTest");
      R1CSProver prover(&prover_transcript, pc_gens_.get());
      auto [com, var] =
          prover.Commit(yacl::math::MPInt(v_val), CreateDummyScalar(curve_));
      commitment = com;
      YACL_ENFORCE(
          RangeProofGadget(&prover, var, std::make_optional(v_val), n).IsOk());
      auto proof_res = prover.Prove(bp_gens.get());
      if (proof_res.IsErr()) {
        return Result<void, R1CSError>::Err(proof_res.Error());
      }
      proof = std::move(proof_res).TakeValue();
    }
    {
      SimpleTranscript verifier_transcript("RangeProofTest");
      R1CSVerifier verifier(&verifier_transcript, curve_);
      auto var = verifier.Commit(commitment);
      YACL_ENFORCE(RangeProofGadget(&verifier, var, std::nullopt, n).IsOk());
      return verifier.Verify(proof, pc_gens_.get(), bp_gens.get());
    }
  }

  std::shared_ptr<yacl::crypto::EcGroup> curve_;
  std::shared_ptr<PedersenGens> pc_gens_;
};

// Define the tests using TEST_F
TEST_F(R1CSTest, ShuffleGadgetK2) { ShuffleTestHelper(2); }
TEST_F(R1CSTest, ShuffleGadgetK3) { ShuffleTestHelper(3); }
TEST_F(R1CSTest, ShuffleGadgetK8) { ShuffleTestHelper(8); }

TEST_F(R1CSTest, ExampleGadget) {
  ASSERT_TRUE(ExampleGadgetRoundtripHelper(3, 4, 6, 1, 40, 9).IsOk());
  ASSERT_TRUE(ExampleGadgetRoundtripHelper(3, 4, 6, 1, 40, 10).IsErr());
}

TEST_F(R1CSTest, RangeProofGadget) {
  for (int n : {2, 10, 32, 63}) {
    uint64_t max_val = (n == 64) ? UINT64_MAX : (1ULL << n) - 1;
    ASSERT_TRUE(RangeProofHelper(max_val, n).IsOk());
    ASSERT_TRUE(RangeProofHelper(0, n).IsOk());
    if (n < 64) {
      ASSERT_TRUE(RangeProofHelper(max_val + 1, n).IsErr());
    }
  }
}

}  // namespace examples::zkp