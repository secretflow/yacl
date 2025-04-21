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

#include "range_proof.h"

#include <memory>
#include <random>
#include <string>

#include "gtest/gtest.h"
#include "yacl/base/exception.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/math/mpint/mp_int.h"
#include "yacl/crypto/ecc/openssl/openssl_group.h"
#include "zkp/bulletproofs/range_proof/range_proof_config.h"
#include "zkp/bulletproofs/simple_transcript.h"

namespace examples::zkp {

using yacl::crypto::EcGroup;
using yacl::crypto::EcPoint;
using yacl::math::MPInt;

class RangeProofTest : public ::testing::Test {
 protected:
  std::shared_ptr<EcGroup> curve_;
  std::unique_ptr<SimpleTranscript> transcript_;

  void SetUp() override {
    using namespace yacl::crypto;
    using namespace yacl::crypto::openssl;
    curve_ = OpensslGroup::Create(GetCurveMetaByName(kRangeProofEcName));
    transcript_ = std::make_unique<SimpleTranscript>(
        yacl::ByteContainerView("test-range-proof"));
  }
};

TEST_F(RangeProofTest, TestValidRange8Bit) {
  // Test values in range [0, 2^8 - 1]
  std::vector<uint64_t> test_values = {127};
  
  for (uint64_t value : test_values) {
    MPInt v;
    v.Set(value);
    
    MPInt blinding;
    MPInt::RandomLtN(curve_->GetOrder(), &blinding);
    
    auto [proof, commitment] = RangeProof::CreateSingle(
        curve_, *transcript_, v, blinding, 8);
        
    auto verify_transcript = std::make_unique<SimpleTranscript>(
        yacl::ByteContainerView("test-range-proof"));
    EXPECT_EQ(proof.VerifySingle(curve_, *verify_transcript, commitment, 8),
              RangeProof::Error::kOk);
  }
}

TEST_F(RangeProofTest, TestInvalidRange8Bit) {
  uint64_t value = 256;  // 2^8
  
  MPInt v;
  v.Set(value);
  
  MPInt blinding;
  MPInt::RandomLtN(curve_->GetOrder(), &blinding);
  
  EXPECT_THROW(RangeProof::CreateSingle(curve_, *transcript_, v, blinding, 8),
               yacl::Exception);
}

TEST_F(RangeProofTest, TestSerialization) {
  uint64_t value = 123;
  
  MPInt v;
  v.Set(value);
  
  MPInt blinding;
  MPInt::RandomLtN(curve_->GetOrder(), &blinding);
  
  auto [proof, commitment] = RangeProof::CreateSingle(
      curve_, *transcript_, v, blinding, 8);
      
  yacl::Buffer proof_bytes = proof.ToBytes();
  EXPECT_GT(proof_bytes.size(), 0);
  
  auto new_transcript = std::make_unique<SimpleTranscript>(
      yacl::ByteContainerView("test-range-proof"));
      
  auto recovered_proof = RangeProof::FromBytes(
      curve_, yacl::ByteContainerView(proof_bytes));
  
  auto verify_result = recovered_proof.VerifySingle(
      curve_, *new_transcript, commitment, 8);
      
  EXPECT_EQ(verify_result, RangeProof::Error::kOk);
}

} // namespace examples::zkp 