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

#include "yacl/crypto/experimental/zkp/bulletproofs/simple_transcript.h"

#include <gtest/gtest.h>

#include "bp_config.h"

#include "yacl/crypto/ecc/curve_meta.h"
#include "yacl/crypto/ecc/openssl/openssl_group.h"

namespace examples::zkp {
namespace {

class SimpleTranscriptTest : public ::testing::Test {
 protected:
  void SetUp() override {
    curve_ = yacl::crypto::EcGroupFactory::Instance().Create(
        kBpEcName, yacl::ArgLib = kBpEcLib);
  }

  std::shared_ptr<yacl::crypto::EcGroup> curve_;
};

TEST_F(SimpleTranscriptTest, CreateTranscript) {
  SimpleTranscript transcript("test-transcript");
}

TEST_F(SimpleTranscriptTest, AppendingMessages) {
  SimpleTranscript transcript;

  // Append various types of data
  transcript.AppendMessage("test", "message");
  transcript.AppendU64("count", 42);

  // Transcript state should have changed internally
  yacl::math::MPInt challenge1 =
      transcript.ChallengeScalar("test-challenge", curve_);

  // Create a fresh transcript with the same inputs
  SimpleTranscript transcript2;
  transcript2.AppendMessage("test", "message");
  transcript2.AppendU64("count", 42);

  // Challenge from the same sequence should be identical
  yacl::math::MPInt challenge2 =
      transcript2.ChallengeScalar("test-challenge", curve_);
  EXPECT_EQ(challenge1, challenge2);

  // Adding different data should result in a different challenge
  transcript2.AppendMessage("extra", "data");
  yacl::math::MPInt challenge3 =
      transcript2.ChallengeScalar("test-challenge", curve_);
  EXPECT_NE(challenge2, challenge3);
}

TEST_F(SimpleTranscriptTest, ScalarOperations) {
  SimpleTranscript transcript;

  // Test with a few different scalars
  yacl::math::MPInt scalar1(123);
  yacl::math::MPInt scalar2(456);

  transcript.AppendScalar("scalar1", scalar1);
  transcript.AppendScalar("scalar2", scalar2);

  // Generate a challenge
  yacl::math::MPInt challenge =
      transcript.ChallengeScalar("test-challenge", curve_);

  // The challenge should be in the proper range
  EXPECT_TRUE(challenge >= yacl::math::MPInt(0));
  EXPECT_TRUE(challenge < curve_->GetOrder());
}

TEST_F(SimpleTranscriptTest, PointOperations) {
  SimpleTranscript transcript;

  // Get the generator point
  yacl::crypto::EcPoint generator = curve_->GetGenerator();

  // Append the generator
  transcript.AppendPoint("point", generator, curve_);

  // Create a second point
  yacl::crypto::EcPoint point2 = curve_->Double(generator);

  // Append the second point
  transcript.AppendPoint("point2", point2, curve_);

  // Generate a challenge
  yacl::math::MPInt challenge =
      transcript.ChallengeScalar("test-challenge", curve_);

  // The challenge should be in the proper range
  EXPECT_TRUE(challenge >= yacl::math::MPInt(0));
  EXPECT_TRUE(challenge < curve_->GetOrder());
}

TEST_F(SimpleTranscriptTest, PointValidation) {
  SimpleTranscript transcript;

  // Get the generator point
  yacl::crypto::EcPoint generator = curve_->GetGenerator();

  // This should succeed
  transcript.ValidateAndAppendPoint("valid-point", generator, curve_);

  // Create an infinity point
  yacl::crypto::EcPoint infinity_point =
      curve_->Add(generator, curve_->Negate(generator));

  // This should throw an exception
  EXPECT_THROW(
      transcript.ValidateAndAppendPoint("infinity", infinity_point, curve_),
      yacl::Exception);
}

TEST_F(SimpleTranscriptTest, DomainSeparators) {
  SimpleTranscript transcript1;
  SimpleTranscript transcript2;

  // Apply domain separators
  transcript1.RangeProofDomainSep(64, 1);
  transcript2.RangeProofDomainSep(64, 1);

  // Challenges should be the same
  yacl::math::MPInt challenge1 = transcript1.ChallengeScalar("test", curve_);
  yacl::math::MPInt challenge2 = transcript2.ChallengeScalar("test", curve_);
  EXPECT_EQ(challenge1, challenge2);

  // Different domain separators should yield different challenges
  SimpleTranscript transcript3;
  transcript3.RangeProofDomainSep(32, 1);  // Different bit size
  yacl::math::MPInt challenge3 = transcript3.ChallengeScalar("test", curve_);
  EXPECT_NE(challenge1, challenge3);

  // Test other domain separators
  SimpleTranscript transcript4;
  transcript4.InnerproductDomainSep(64);
  yacl::math::MPInt challenge4 = transcript4.ChallengeScalar("test", curve_);
  EXPECT_NE(challenge1, challenge4);
}

TEST_F(SimpleTranscriptTest, ChallengeBytes) {
  SimpleTranscript transcript;

  // Append some data
  transcript.AppendMessage("test", "message");

  // Get challenge bytes of different lengths
  std::array<uint8_t, 32> bytes32{};
  transcript.ChallengeBytes("challenge32", bytes32.data(), bytes32.size());

  std::array<uint8_t, 64> bytes64{};
  transcript.ChallengeBytes("challenge64", bytes64.data(), bytes64.size());

  // The first 32 bytes should be different because the label is different
  bool all_same = true;
  for (size_t i = 0; i < 32; i++) {
    if (bytes32[i] != bytes64[i]) {
      all_same = false;
      break;
    }
  }
  EXPECT_FALSE(all_same);

  // Get another 32 bytes with the same label
  std::array<uint8_t, 32> bytes32_again{};
  SimpleTranscript transcript2;
  transcript2.AppendMessage("test", "message");
  transcript2.ChallengeBytes("challenge32", bytes32_again.data(),
                             bytes32_again.size());

  // These should be the same
  for (size_t i = 0; i < 32; i++) {
    EXPECT_EQ(bytes32[i], bytes32_again[i]);
  }
}

}  // namespace
}  // namespace examples::zkp

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}