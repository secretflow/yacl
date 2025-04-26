#include "zkp/bulletproofs/range_proof/range_proof.h"

#include <gtest/gtest.h>

#include "yacl/crypto/ecc/openssl/openssl_group.h"
#include "yacl/crypto/ecc/curve_meta.h"
#include "range_proof_config.h"
#include "zkp/bulletproofs/simple_transcript.h"

namespace examples::zkp {
namespace {

class RangeProofTest : public ::testing::Test {
 protected:
  void SetUp() override {
    curve_ = yacl::crypto::EcGroupFactory::Instance().Create(
       kRangeProofEcName,
        yacl::ArgLib = kRangeProofEcLib);
    transcript_ = std::make_unique<SimpleTranscript>(
        yacl::ByteContainerView("test-range-proof"));
  }

  std::shared_ptr<yacl::crypto::EcGroup> curve_;
  std::unique_ptr<SimpleTranscript> transcript_;
};

TEST_F(RangeProofTest, TestValidRange8Bit) {
  uint64_t value = 123;
  
  yacl::math::MPInt v(value);
  
  yacl::math::MPInt blinding;
  yacl::math::MPInt::RandomExactBits(curve_->GetField().BitCount(), &blinding);
  
  auto [proof, commitment] = RangeProof::CreateSingle(
      curve_, *transcript_, value, blinding, 8);
      
  auto verify_transcript = std::make_unique<SimpleTranscript>(
      yacl::ByteContainerView("test-range-proof"));
      
  EXPECT_EQ(proof.VerifySingle(curve_, *verify_transcript, commitment, 8), 
            ProofError::kOk);
}

TEST_F(RangeProofTest, TestInvalidRange8Bit) {
  // Value 256 is outside the 8-bit range [0, 2^8)
  uint64_t value = 256;
  
  yacl::math::MPInt v(value);
  
  yacl::math::MPInt blinding;
  yacl::math::MPInt::RandomExactBits(curve_->GetField().BitCount(), &blinding);
  
  auto [proof, commitment] = RangeProof::CreateSingle(
      curve_, *transcript_, value, blinding, 8);
      
  auto verify_transcript = std::make_unique<SimpleTranscript>(
      yacl::ByteContainerView("test-range-proof"));
      
  EXPECT_NE(proof.VerifySingle(curve_, *verify_transcript, commitment, 8), 
            ProofError::kOk);
}

TEST_F(RangeProofTest, TestMultipleProofs) {
  std::vector<uint64_t> values = {1, 5, 10, 50};
  
  std::vector<yacl::math::MPInt> blindings;
  for (size_t i = 0; i < values.size(); i++) {
    yacl::math::MPInt blinding;
    yacl::math::MPInt::RandomExactBits(curve_->GetField().BitCount(), &blinding);
    blindings.push_back(blinding);
  }
  
  auto [proof, commitments] = RangeProof::CreateMultiple(
      curve_, *transcript_, values, blindings, 8);
      
  auto verify_transcript = std::make_unique<SimpleTranscript>(
      yacl::ByteContainerView("test-range-proof"));
      
  EXPECT_EQ(proof.VerifyMultiple(curve_, *verify_transcript, commitments, 8), 
            ProofError::kOk);
}

TEST_F(RangeProofTest, TestSerialization) {
  uint64_t value = 123;
  
  yacl::math::MPInt v(value);
  
  yacl::math::MPInt blinding;
  yacl::math::MPInt::RandomExactBits(curve_->GetField().BitCount(), &blinding);
  
  auto [proof, commitment] = RangeProof::CreateSingle(
      curve_, *transcript_, value, blinding, 8);
      
  yacl::Buffer proof_bytes = proof.ToBytes(curve_);
  EXPECT_GT(proof_bytes.size(), 0);
  
  auto new_transcript = std::make_unique<SimpleTranscript>(
      yacl::ByteContainerView("test-range-proof"));
      
  auto recovered_proof = RangeProof::FromBytes(
      curve_, yacl::ByteContainerView(proof_bytes));
  
  auto verify_result = recovered_proof.VerifySingle(
      curve_, *new_transcript, commitment, 8);
      
  EXPECT_EQ(verify_result, ProofError::kOk);
}

} // namespace
} // namespace examples::zkp

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}