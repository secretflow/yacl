// Copyright 2023 Ant Group Co., Ltd.
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

#include <gtest/gtest.h>
#include <limits>  // For UINT64_MAX
#include <memory>
#include <vector>
#include "range_proof_config.h"
#include "zkp/bulletproofs/simple_transcript.h"  // For SimpleTranscript
#include "yacl/crypto/ecc/ecc_spi.h"  // For EcGroupFactory, EcGroup
#include "yacl/crypto/rand/rand.h"    // For random scalars and bytes
#include "zkp/bulletproofs/range_proof/range_proof.h"


namespace examples::zkp {
namespace {

// Helper to generate random value in range [0, 2^n - 2] for testing
// Matches  test range [0, (1 << (n-1)) -1], adjusting for n=64
// Let's actually match the range used in  tests: [0, 2^(n-1) - 1]
uint64_t GenerateRandomValueInRange(
    size_t n, const std::shared_ptr<yacl::crypto::EcGroup>& curve) {
  if (n == 0) return 0;
  //  test uses gen_range(0, (1 << (n - 1)) - 1);
  // This means the max value is 2^(n-1) - 2.
  // If n=1, max value is 2^0 - 2 = -1 -> range is just 0.
  // If n=8, max value is 2^7 - 2 = 126. Range [0, 126].
  // If n=64, max value is 2^63 - 2.
  if (n == 1) return 0;

  uint64_t upper_bound_exclusive;
  if (n - 1 >= 64) {  // If n=64 or more (though we restrict n<=64)
    upper_bound_exclusive = std::numeric_limits<uint64_t>::
        max();  // 2^64 - 1
                // Need 2^63 - 1 for the actual upper bound (exclusive)
                // This is hard to represent perfectly, just generate < 2^63
    upper_bound_exclusive = 1ULL << 63;  // Max value generated will be 2^63 - 1
  } else {
    upper_bound_exclusive = 1ULL << (n - 1);
  }

  if (upper_bound_exclusive <= 1) return 0;  // Handle n=1 case

  yacl::math::MPInt v_mp;
  // Generate random number < upper_bound_exclusive
  v_mp.RandomLtN(yacl::math::MPInt(upper_bound_exclusive), &v_mp);
  return v_mp.Get<uint64_t>();
}

class RangeProofDirectTest : public ::testing::Test {
 protected:
  void SetUp() override {
    curve_ = yacl::crypto::EcGroupFactory::Instance().Create(
        kRangeProofEcName, yacl::ArgLib = kRangeProofEcLib);
  }

  // Helper to run create/verify for a given bitsize n
  void TestGenerateAndVerify(size_t n) {
    // Generate value and blinding
    uint64_t v = GenerateRandomValueInRange(n, curve_);  // Use helper for range
    yacl::math::MPInt v_blinding;
    v_blinding.RandomLtN(curve_->GetOrder(), &v_blinding);

    // Prover side
    SimpleTranscript prover_transcript("RangeproofTest");  // Match  label
    RangeProof proof;
    ASSERT_NO_THROW({
      proof = RangeProof::GenerateProof(prover_transcript, curve_, n, v,
                                        v_blinding);
    });

    // Verifier side
    SimpleTranscript verifier_transcript(
        "RangeproofTest");  // MUST use same label
    bool verification_result = false;
    ASSERT_NO_THROW({
      verification_result = proof.Verify(verifier_transcript, curve_, n);
    });

    // Add debug printing
    if (!verification_result) {
      std::cout << "Verification failed for n=" << n << ", v=" << v
                << std::endl;
      // Optionally serialize proof parts for debugging
      // std::cout << "Proof V: " << curve_->SerializePoint(proof.GetV()) <<
      // std::endl;
      // ...
    }

    ASSERT_TRUE(verification_result)
        << "Verification failed for n=" << n << ", v=" << v;

    // Test Serialization/Deserialization
    yacl::Buffer proof_bytes;
    ASSERT_NO_THROW({ proof_bytes = proof.ToBytes(curve_); });
    ASSERT_NE(proof_bytes.size(), 0);

    RangeProof deserialized_proof;
    ASSERT_NO_THROW(
        { deserialized_proof = RangeProof::FromBytes(curve_, proof_bytes); });

    // Verify deserialized proof
    SimpleTranscript verifier_transcript2("RangeproofTest");
    bool verification_result2 = false;
    ASSERT_NO_THROW({
      verification_result2 =
          deserialized_proof.Verify(verifier_transcript2, curve_, n);
    });
    ASSERT_TRUE(verification_result2)
        << "Verification failed after serde for n=" << n;
  }

  std::shared_ptr<yacl::crypto::EcGroup> curve_;
};

// Test cases for different bit sizes matching  tests
TEST_F(RangeProofDirectTest, CreateAndVerify8) { TestGenerateAndVerify(8); }

TEST_F(RangeProofDirectTest, CreateAndVerify16) { TestGenerateAndVerify(16); }

TEST_F(RangeProofDirectTest, CreateAndVerify32) { TestGenerateAndVerify(32); }

TEST_F(RangeProofDirectTest, CreateAndVerify64) { TestGenerateAndVerify(64); }

}  // namespace
}  // namespace examples::zkp

// Boilerplate main function for Google Test
int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}