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

#include "gtest/gtest.h"
#include "yacl/base/exception.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/math/mpint/mp_int.h"
#include "yacl/crypto/ecc/openssl/openssl_group.h"
#include "zkp/bulletproofs/range_proof/range_proof_config.h"
#include "zkp/bulletproofs/simple_transcript.h"

namespace examples::zkp {

using namespace yacl::crypto;
using namespace yacl::math;
using examples::zkp::VartimeMultiscalarMul;

class RangeProofTest : public ::testing::Test {
 protected:
  std::shared_ptr<yacl::crypto::EcGroup> curve_;

  void SetUp() override {
    using namespace yacl::crypto;
    using namespace yacl::crypto::openssl;
    curve_ = OpensslGroup::Create(GetCurveMetaByName(kRangeProofEcName));
    transcript_ = std::make_unique<SimpleTranscript>(
        yacl::ByteContainerView("test-range-proof"));
  }

  std::unique_ptr<SimpleTranscript> transcript_;
};

TEST_F(RangeProofTest, TestValidRange8Bit) {
  // Test values in range [0, 2^8 - 1]
  std::vector<uint64_t> test_values = {0, 1, 127, 255};
  
  for (uint64_t value : test_values) {
    yacl::math::MPInt v;
    v.Set(value);
    
    // Generate random blinding factor
    yacl::math::MPInt blinding;
    yacl::math::MPInt::RandomLtN(curve_->GetOrder(), &blinding);
    
    auto [proof, commitment] = RangeProof::CreateSingle(
        curve_, *transcript_, v, blinding, 8);
        
    EXPECT_EQ(proof.VerifySingle(curve_, *transcript_, commitment, 8),
              RangeProof::Error::kOk);
  }
}

TEST_F(RangeProofTest, TestInvalidRange8Bit) {
  // Test value outside range [0, 2^8 - 1]
  uint64_t value = 256;  // 2^8
  
  yacl::math::MPInt v;
  v.Set(value);
  
  // Generate random blinding factor
  yacl::math::MPInt blinding;
  yacl::math::MPInt::RandomLtN(curve_->GetOrder(), &blinding);
  
  EXPECT_THROW(
      RangeProof::CreateSingle(curve_, *transcript_, v, blinding, 8),
      yacl::Exception);
}

TEST_F(RangeProofTest, TestSerialization) {
  // Test serialization/deserialization
  uint64_t value = 123;
  
  yacl::math::MPInt v;
  v.Set(value);
  
  // Generate random blinding factor
  yacl::math::MPInt blinding;
  yacl::math::MPInt::RandomLtN(curve_->GetOrder(), &blinding);
  
  auto [proof, commitment] = RangeProof::CreateSingle(
      curve_, *transcript_, v, blinding, 8);
      
  // Serialize
  yacl::Buffer proof_bytes = proof.ToBytes();
  
  // Deserialize
  auto recovered_proof = RangeProof::FromBytes(
      curve_, yacl::ByteContainerView(proof_bytes.data(), proof_bytes.size()));
  
  // Verify recovered proof
  EXPECT_EQ(recovered_proof.VerifySingle(curve_, *transcript_, commitment, 8),
            RangeProof::Error::kOk);
}

} // namespace examples::zkp 