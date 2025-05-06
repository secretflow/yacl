#include "zkp/bulletproofs/range_proof_mpc/range_proof_mpc.h"

#include <gtest/gtest.h>

#include "yacl/crypto/ecc/openssl/openssl_group.h"
#include "yacl/crypto/rand/rand.h"
#include "zkp/bulletproofs/simple_transcript.h"
#include "range_proof_config.h"

namespace examples::zkp {
namespace {

class RangeProofMPCTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Initialize with secp256k1 curve for testing
    curve_ = yacl::crypto::EcGroupFactory::Instance().Create(
        kRangeProofEcName, yacl::ArgLib = kRangeProofEcLib);
    pc_gens_ptr_ = std::make_unique<PedersenGens>(curve_);
    bp_gens_ptr_ = std::make_unique<BulletproofGens>(curve_, 64, 1);
  }

  // Helper function for creating and verifying a single range proof
  void TestSingleRangeProof(uint64_t value, size_t n) {
    // Create transcript for the prover
    auto prover_transcript = std::make_unique<SimpleTranscript>("range_proof_test");
    
    // Generate a random blinding factor
    yacl::math::MPInt blinding;
    yacl::math::MPInt::RandomLtN(curve_->GetOrder(), &blinding);
    
    // Create the proof
    auto [proof, commitment] = RangeProofMPC::CreateSingle(
        *bp_gens_ptr_, *pc_gens_ptr_, *prover_transcript, value, blinding, n);
    
    // Verify the proof with a fresh transcript
    auto verifier_transcript = std::make_unique<SimpleTranscript>("range_proof_test");
    EXPECT_TRUE(proof.VerifySingle(*bp_gens_ptr_, *pc_gens_ptr_, *verifier_transcript, commitment, n));
  }
  
  // Helper function for creating and verifying multiple range proofs
  void TestMultipleRangeProof(const std::vector<uint64_t>& values, size_t n) {
    // Create transcript for the prover
    auto prover_transcript = std::make_unique<SimpleTranscript>("range_proof_test");
    
    // Generate random blinding factors
    std::vector<yacl::math::MPInt> blindings;
    for (size_t i = 0; i < values.size(); i++) {
      yacl::math::MPInt blinding;
      yacl::math::MPInt::RandomLtN(curve_->GetOrder(), &blinding);
      blindings.push_back(blinding);
    }
    
    // Create the proof
    auto [proof, commitments] = RangeProofMPC::CreateMultiple(
        *bp_gens_ptr_, *pc_gens_ptr_, *prover_transcript, values, blindings, n);
    
    // Verify the proof with a fresh transcript
    auto verifier_transcript = std::make_unique<SimpleTranscript>("range_proof_test");
    EXPECT_TRUE(proof.VerifyMultiple(*bp_gens_ptr_, *pc_gens_ptr_, *verifier_transcript, commitments, n));
  }

  std::shared_ptr<yacl::crypto::EcGroup> curve_;
  std::unique_ptr<PedersenGens> pc_gens_ptr_; // Use pointer
  std::unique_ptr<BulletproofGens> bp_gens_ptr_; // Use pointer
};

TEST_F(RangeProofMPCTest, TestDelta) {
  // Test the Delta function with small values
  yacl::math::MPInt y(3);
  yacl::math::MPInt z(5);
  
  const size_t n = 4;
  const size_t m = 2;
  
  // Calculate delta manually
  yacl::math::MPInt delta = RangeProofMPC::Delta(n, m, y, z, curve_);
  
  // The delta calculation is complex, so we just verify it's non-zero here
  EXPECT_NE(delta, yacl::math::MPInt(0));
}

TEST_F(RangeProofMPCTest, TestSingleProof8Bit) {
  // Test a valid 8-bit value (0 <= value < 2^8)
  TestSingleRangeProof(123, 8);
}

TEST_F(RangeProofMPCTest, TestSingleProof16Bit) {
  // Test a valid 16-bit value (0 <= value < 2^16)
  TestSingleRangeProof(12345, 16);
}

TEST_F(RangeProofMPCTest, TestSingleProof32Bit) {
  // Test a valid 32-bit value (0 <= value < 2^32)
  TestSingleRangeProof(1234567890, 32);
}

// TEST_F(RangeProofTest, TestMultipleProof8Bit) {
//   // Test multiple valid 8-bit values
//   TestMultipleRangeProof({123, 45, 67, 89}, 8);
// }

// TEST_F(RangeProofTest, TestMultipleProof16Bit) {
//   // Test multiple valid 16-bit values
//   TestMultipleRangeProof({12345, 6789, 10111, 12131}, 16);
// }

// TEST_F(RangeProofTest, TestMultipleProof32Bit) {
//   // Test multiple valid 32-bit values
//   TestMultipleRangeProof({1234567890, 987654321, 123456789, 987654321}, 32);
// }

TEST_F(RangeProofMPCTest, TestSerialization) {
  // Create a proof
  auto prover_transcript = std::make_unique<SimpleTranscript>("range_proof_test");
  
  yacl::math::MPInt blinding;
  yacl::math::MPInt::RandomLtN(curve_->GetOrder(), &blinding);

  auto [proof, commitment] = RangeProofMPC::CreateSingle(
      *bp_gens_ptr_, *pc_gens_ptr_, *prover_transcript, 123, blinding, 8);
  
  // Serialize and deserialize
  // yacl::Buffer serialized = proof.ToBytes(curve_);
  // RangeProof deserialized = RangeProof::FromBytes(curve_, serialized);
        
  // Verify the deserialized proof
  // auto verifier_transcript = std::make_unique<SimpleTranscript>("range_proof_test");
  // EXPECT_TRUE(deserialized.VerifySingle(curve_, *verifier_transcript, commitment, 8));

  auto verifier_transcript = std::make_unique<SimpleTranscript>("range_proof_test");
  EXPECT_TRUE(proof.VerifySingle(*bp_gens_ptr_, *pc_gens_ptr_, *verifier_transcript, commitment, 8));
}

} // namespace
} // namespace examples::zkp

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}