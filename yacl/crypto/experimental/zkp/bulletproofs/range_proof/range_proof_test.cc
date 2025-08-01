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

#include "yacl/crypto/experimental/zkp/bulletproofs/range_proof/range_proof.h"

#include <gtest/gtest.h>

#include <limits>
#include <memory>
#include <vector>

#include "range_proof_config.h"

#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/crypto/experimental/zkp/bulletproofs/generators.h"
#include "yacl/crypto/experimental/zkp/bulletproofs/simple_transcript.h"
#include "yacl/crypto/rand/rand.h"

namespace examples::zkp {
namespace {

class RangeProofTest : public ::testing::Test {
 protected:
  void SetUp() override {
    curve_ = yacl::crypto::EcGroupFactory::Instance().Create(
        kRangeProofEcName, yacl::ArgLib = kRangeProofEcLib);
  }

  // It creates a proof for `m` values of `n` bits each, and verifies it.
  void TestCreateAndVerifyHelper(size_t n, size_t m) {
    // 1. Setup: Generators are accessible to both Prover and Verifier.
    // The party_capacity must be at least m.
    const size_t max_parties = 8;
    YACL_ENFORCE(m <= max_parties, "Test party size exceeds max capacity");
    auto bp_gens = std::make_shared<BulletproofGens>(curve_, 64, max_parties);
    auto pc_gens = std::make_shared<PedersenGens>(curve_);

    yacl::Buffer proof_bytes;
    std::vector<yacl::crypto::EcPoint> value_commitments;

    // 2. Prover's scope
    {
      auto prover_transcript =
          std::make_shared<SimpleTranscript>("AggregatedRangeProofTest");

      // 2.1. Create witness data
      std::vector<uint64_t> values;
      std::vector<yacl::math::MPInt> blindings;
      uint64_t max_value = (n == 64) ? UINT64_MAX - 1 : (1ULL << n);
      if (max_value == 0) max_value = 1;  // Handle n=0 case for RandomLtN

      for (size_t i = 0; i < m; ++i) {
        yacl::math::MPInt v_mp;
        v_mp.RandomLtN(yacl::math::MPInt(max_value), &v_mp);
        values.push_back(v_mp.Get<uint64_t>());
        blindings.push_back(CreateRandomScalar(curve_));
      }

      // 2.2. Create the proof
      auto prove_res = RangeProof::ProveMultiple(
          prover_transcript, curve_, bp_gens, pc_gens, values, blindings, n);
      ASSERT_TRUE(prove_res.IsOk());
      auto prove_pair = std::move(prove_res).TakeValue();
      RangeProof proof = std::move(prove_pair.first);
      value_commitments = std::move(prove_pair.second);

      // 2.3. Serialize the proof
      proof_bytes = proof.ToBytes(curve_);
    }

    // 3. Verifier's scope
    {
      // 3.1. Deserialize the proof
      RangeProof proof = RangeProof::FromBytes(curve_, proof_bytes);
      // 3.2. Verify with a fresh transcript
      auto verifier_transcript =
          std::make_shared<SimpleTranscript>("AggregatedRangeProofTest");
      bool verify_ok = proof.VerifyMultiple(
          verifier_transcript, curve_, bp_gens, pc_gens, value_commitments, n);

      // Add a helpful message in case of failure
      if (!verify_ok) {
        FAIL() << "Proof verification failed for n=" << n << ", m=" << m;
      }
      ASSERT_TRUE(verify_ok);
    }
  }

  std::shared_ptr<yacl::crypto::EcGroup> curve_;
};

TEST_F(RangeProofTest, CreateAndVerify_n32_m1) {
  TestCreateAndVerifyHelper(32, 1);
}

TEST_F(RangeProofTest, CreateAndVerify_n32_m2) {
  TestCreateAndVerifyHelper(32, 2);
}

TEST_F(RangeProofTest, CreateAndVerify_n32_m4) {
  TestCreateAndVerifyHelper(32, 4);
}

TEST_F(RangeProofTest, CreateAndVerify_n32_m8) {
  TestCreateAndVerifyHelper(32, 8);
}

TEST_F(RangeProofTest, CreateAndVerify_n64_m1) {
  TestCreateAndVerifyHelper(64, 1);
}

TEST_F(RangeProofTest, CreateAndVerify_n64_m2) {
  TestCreateAndVerifyHelper(64, 2);
}

TEST_F(RangeProofTest, CreateAndVerify_n64_m4) {
  TestCreateAndVerifyHelper(64, 4);
}

TEST_F(RangeProofTest, CreateAndVerify_n64_m8) {
  TestCreateAndVerifyHelper(64, 8);
}

TEST_F(RangeProofTest, TestDelta) {
  const size_t n = 256;
  yacl::math::MPInt y = CreateRandomScalar(curve_);
  yacl::math::MPInt z = CreateRandomScalar(curve_);
  const auto& order = curve_->GetOrder();

  yacl::math::MPInt z2 = z.MulMod(z, order);
  yacl::math::MPInt z3 = z2.MulMod(z, order);
  yacl::math::MPInt power_g(0);
  yacl::math::MPInt exp_y(1);
  yacl::math::MPInt exp_2(1);

  for (size_t i = 0; i < n; ++i) {
    power_g = power_g.AddMod((z.SubMod(z2, order)).MulMod(exp_y, order), order);
    power_g = power_g.SubMod(z3.MulMod(exp_2, order), order);
    exp_y = exp_y.MulMod(y, order);
    exp_2 = exp_2.AddMod(exp_2, order);
  }

  // Call the actual Delta function for m=1
  yacl::math::MPInt delta_val = RangeProof::Delta(n, 1, y, z, curve_);

  EXPECT_EQ(power_g, delta_val);
}

}  // namespace
}  // namespace examples::zkp

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}