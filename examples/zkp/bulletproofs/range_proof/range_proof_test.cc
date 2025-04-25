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
    
    BulletproofGens bp_gens(curve_, 64, 4);
    PedersenGens pc_gens(curve_);
    auto [proof, commitment] = RangeProof::CreateSingle(
        bp_gens, pc_gens, curve_, *transcript_, v, blinding, 8);
        
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
  
  BulletproofGens bp_gens(curve_, 64, 4);
  PedersenGens pc_gens(curve_);
  EXPECT_THROW(RangeProof::CreateSingle(bp_gens, pc_gens, curve_, *transcript_, v, blinding, 8),
               yacl::Exception);
}

TEST_F(RangeProofTest, TestDelta) {
  // Choose n = 256 to ensure we overflow the group order during computation
  const size_t n = 256;
  const size_t m = 1;
  const MPInt& order = curve_->GetOrder();
  
  // Generate random y and z
  MPInt y, z;
  MPInt::RandomLtN(order, &y);
  MPInt::RandomLtN(order, &z);
  
  // Compute delta using the optimized implementation
  MPInt optimized_delta = RangeProof::ComputeDelta(n, m, y, z, order);
  
  // Compute delta using the naive implementation for verification
  MPInt z2, z3;
  MPInt::MulMod(z, z, order, &z2);  // z^2
  MPInt::MulMod(z2, z, order, &z3);  // z^3
  
  MPInt power_g;
  power_g.SetZero();
  
  MPInt exp_y, exp_2;
  exp_y.Set(1);  // y^0 = 1
  exp_2.Set(1);  // 2^0 = 1
  
  MPInt two;
  two.Set(2);
  
  MPInt z_minus_z2;
  MPInt::SubMod(z, z2, order, &z_minus_z2);  // z - z^2
  
  for (size_t i = 0; i < n; i++) {
    // power_g += (z - z^2) * exp_y - z^3 * exp_2
    MPInt term1, term2, temp;
    
    // Calculate (z - z^2) * exp_y
    MPInt::MulMod(z_minus_z2, exp_y, order, &term1);
    
    // Calculate z^3 * exp_2
    MPInt::MulMod(z3, exp_2, order, &term2);
    
    // Subtract term2 from term1
    MPInt::SubMod(term1, term2, order, &temp);
    
    // Add to power_g
    MPInt::AddMod(power_g, temp, order, &power_g);
    
    // Update exp_y = exp_y * y
    MPInt::MulMod(exp_y, y, order, &exp_y);
    
    // Update exp_2 = exp_2 * 2
    MPInt::MulMod(exp_2, two, order, &exp_2);
  }
  
  // Verify that both implementations give the same result
  EXPECT_TRUE(power_g.Compare(optimized_delta) == 0);
}

// TEST_F(RangeProofTest, TestSerialization) {
//   uint64_t value = 123;
  
//   MPInt v;
//   v.Set(value);
  
//   MPInt blinding;
//   MPInt::RandomLtN(curve_->GetOrder(), &blinding);
  
//   auto [proof, commitment] = RangeProof::CreateSingle(
//       curve_, *transcript_, v, blinding, 8);
      
//   yacl::Buffer proof_bytes = proof.ToBytes(curve_);
//   EXPECT_GT(proof_bytes.size(), 0);
  
//   auto new_transcript = std::make_unique<SimpleTranscript>(
//       yacl::ByteContainerView("test-range-proof"));
      
//   auto recovered_proof = RangeProof::FromBytes(
//       curve_, yacl::ByteContainerView(proof_bytes));
  
//   auto verify_result = recovered_proof.VerifySingle(
//       curve_, *new_transcript, commitment, 8);
      
//   EXPECT_EQ(verify_result, RangeProof::Error::kOk);
// }

} // namespace examples::zkp 