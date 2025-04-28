#include "zkp/bulletproofs/inner_product_proof.h"

#include <gtest/gtest.h>
#include <memory>
#include <vector>

#include "yacl/crypto/hash/hash_utils.h"
#include "zkp/bulletproofs/generators.h"
#include "zkp/bulletproofs/util.h"

namespace examples::zkp {
namespace {

class InnerProductProofTest : public ::testing::Test {
 protected:
  void SetUp() override {
    try {
      // Set up the curve
      curve_ = yacl::crypto::EcGroupFactory::Instance().Create(
       "secp256k1",
        yacl::ArgLib = "openssl");
      ec_available_ = true;
    } catch (const yacl::Exception& e) {
      ec_available_ = false;
      std::cerr << "Warning: EC operations not available, skipping EC tests: " 
                << e.what() << std::endl;
    }
  }
  
  // Helper to create and verify an inner product proof
  void TestCreateAndVerify(size_t n) {
    if (!ec_available_) {
      GTEST_SKIP() << "Skipping test because EC operations are not available";
    }
    
    // Create bulletproof generators
    BulletproofGens bp_gens(curve_, n, 1);
    
    // Extract G and H vectors
    std::vector<yacl::crypto::EcPoint> G;
    std::vector<yacl::crypto::EcPoint> H;
    
    auto share = bp_gens.Share(0);
    auto G_iter = share.G(n);
    auto H_iter = share.H(n);
    
    G.insert(G.end(), G_iter.begin(), G_iter.end());
    H.insert(H.end(), H_iter.begin(), H_iter.end());
    
    // Generate a random Q point by hashing a test string
    std::string test_string = "test point";
    auto hash = yacl::crypto::Sha256(
        yacl::ByteContainerView(test_string.data(), test_string.size()));
    yacl::crypto::EcPoint Q = curve_->HashToCurve(
        yacl::ByteContainerView(hash.data(), hash.size()));
    
    // Generate random vectors a and b
    std::vector<yacl::math::MPInt> a, b;
    for (size_t i = 0; i < n; i++) {
      yacl::math::MPInt a_i, b_i;
      yacl::math::MPInt::RandomLtN(curve_->GetOrder(), &a_i);
      yacl::math::MPInt::RandomLtN(curve_->GetOrder(), &b_i);
      a.push_back(a_i);
      b.push_back(b_i);
    }
    
    // Compute the inner product c = <a,b>
    yacl::math::MPInt c = InnerProduct(a, b);
    
    // Set up G_factors and H_factors
    std::vector<yacl::math::MPInt> G_factors(n, yacl::math::MPInt(1));
    
    // y_inv is a random challenge
    yacl::math::MPInt y_inv;
    yacl::math::MPInt::RandomLtN(curve_->GetOrder(), &y_inv);
    
    // Compute H_factors = [y_inv^0, y_inv^1, y_inv^2, ...]
    std::vector<yacl::math::MPInt> H_factors;
    H_factors.reserve(n);
    
    yacl::math::MPInt y_pow(1);
    for (size_t i = 0; i < n; i++) {
      H_factors.push_back(y_pow);
      y_pow = y_pow.MulMod(y_inv, curve_->GetOrder());
    }
    
    // Compute P = <a,G> + <b',H> + <a,b>Q
    // where b' = b ⊙ y^(-n) - elementwise multiplication
    std::vector<yacl::math::MPInt> scalars;
    std::vector<yacl::crypto::EcPoint> points;
    
    // <a,G> terms
    for (size_t i = 0; i < n; i++) {
      scalars.push_back(a[i]);
      points.push_back(G[i]);
    }
    
    // <b',H> terms
    for (size_t i = 0; i < n; i++) {
      scalars.push_back(b[i] * H_factors[i]);
      points.push_back(H[i]);
    }
    
    // <a,b>Q term
    scalars.push_back(c);
    points.push_back(Q);
    
    // Compute P
    yacl::crypto::EcPoint P = MultiScalarMul(curve_, scalars, points);
    
    // Create a transcript and the proof
    SimpleTranscript prover_transcript("innerproducttest");
    InnerProductProof proof = InnerProductProof::Create(
        &prover_transcript,
        curve_,
        Q,
        G_factors,
        H_factors,
        G,
        H,
        a,
        b);
    
    // Verify the proof
    SimpleTranscript verifier_transcript("innerproducttest");
    
    bool result = proof.Verify(
        n,
        &verifier_transcript,
        curve_,
        G_factors,
        H_factors,
        P,
        Q,
        G,
        H);

    EXPECT_TRUE(result);
    
    // Only perform serialization test if verification passed
    if (result) {
      // Test serialization/deserialization
      yacl::Buffer proof_bytes = proof.ToBytes(curve_);
      InnerProductProof deserialized_proof = 
          InnerProductProof::FromBytes(proof_bytes, curve_);
      
      // Verify the deserialized proof
      SimpleTranscript verify2_transcript("innerproducttest");
      bool result2 = deserialized_proof.Verify(
          n,
          &verify2_transcript,
          curve_,
          G_factors,
          H_factors,
          P,
          Q,
          G,
          H);
      
      EXPECT_TRUE(result2);
    }


  }

  std::shared_ptr<yacl::crypto::EcGroup> curve_;
  bool ec_available_ = false;
};

TEST_F(InnerProductProofTest, TestInnerProduct) {
  std::vector<yacl::math::MPInt> a = {
    yacl::math::MPInt(1),
    yacl::math::MPInt(2),
    yacl::math::MPInt(3),
    yacl::math::MPInt(4)
  };
  
  std::vector<yacl::math::MPInt> b = {
    yacl::math::MPInt(2),
    yacl::math::MPInt(3),
    yacl::math::MPInt(4),
    yacl::math::MPInt(5)
  };
  
  EXPECT_EQ(InnerProduct(a, b), yacl::math::MPInt(40));
}

TEST_F(InnerProductProofTest, MakeIPP1) {
  TestCreateAndVerify(1);
}

TEST_F(InnerProductProofTest, MakeIPP2) {
  TestCreateAndVerify(2);
}

TEST_F(InnerProductProofTest, MakeIPP4) {
  TestCreateAndVerify(4);
}

TEST_F(InnerProductProofTest, MakeIPP8) {
  TestCreateAndVerify(8);
}

TEST_F(InnerProductProofTest, MakeIPP16) {
  TestCreateAndVerify(16);
}

TEST_F(InnerProductProofTest, MakeIPP32) {
  TestCreateAndVerify(32);
}

TEST_F(InnerProductProofTest, MakeIPP64) {
  TestCreateAndVerify(64);
}



} // namespace
} // namespace examples::zkp

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}