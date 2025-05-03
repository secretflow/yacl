#include "zkp/bulletproofs/inner_product_proof.h"

#include <gtest/gtest.h>
#include <memory>
#include <vector>

#include "yacl/base/exception.h"
#include "yacl/crypto/ecc/ecc_spi.h"        // For EcGroupFactory, EcGroup
#include "yacl/crypto/rand/rand.h"         // For random scalars/points
#include "zkp/bulletproofs/simple_transcript.h" // For SimpleTranscript
#include "zkp/bulletproofs/util.h"         // For helpers

namespace examples::zkp {
namespace {

// Helper to create generators based on hashing base points (matches range_proof.rs)
std::vector<yacl::crypto::EcPoint> MakeGeneratorsFromHashedBase(
    const std::string& base_seed,
    size_t n,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve) {

    yacl::crypto::EcPoint base_point = curve->HashToCurve(
        yacl::crypto::HashToCurveStrategy::Autonomous, base_seed);

    std::vector<yacl::crypto::EcPoint> generators(n);
    if (n == 0) return generators;

    // Seed for first generator: hash of base_point's compressed bytes
    yacl::Buffer base_bytes = curve->SerializePoint(base_point); // Compressed
    generators[0] = curve->HashToCurve(yacl::crypto::HashToCurveStrategy::Autonomous,
                                       yacl::ByteContainerView(base_bytes));

    // Generate subsequent points by hashing previous one's compressed bytes
    for (size_t i = 1; i < n; ++i) {
        yacl::Buffer prev_bytes = curve->SerializePoint(generators[i-1]); // Compressed
        generators[i] = curve->HashToCurve(yacl::crypto::HashToCurveStrategy::Autonomous,
                                           yacl::ByteContainerView(prev_bytes));
    }
    return generators;
}

class InnerProductProofTest : public ::testing::Test {
 protected:
  void SetUp() override {
    curve_ = yacl::crypto::EcGroupFactory::Instance().Create(
        "secp256k1", yacl::ArgLib = "openssl");
    order_ = curve_->GetOrder();
  }

  // Replicates the test logic from Rust
  void TestHelperCreate(size_t n) {
    // 1. Setup
    auto transcript_label = "innerproducttest";
    yacl::math::MPInt one(1);

    // Generators G, H derived like in range_proof.rs
    auto G_vec = MakeGeneratorsFromHashedBase("hello", n, curve_);
    auto H_vec = MakeGeneratorsFromHashedBase("there", n, curve_);

    // Random Q point
    yacl::crypto::EcPoint Q = curve_->HashToCurve(
        yacl::crypto::HashToCurveStrategy::Autonomous, "test point");

    // Random witness vectors a, b
    std::vector<yacl::math::MPInt> a_vec(n), b_vec(n);
    for(size_t i=0; i<n; ++i) {
        a_vec[i].RandomLtN(order_, &a_vec[i]);
        b_vec[i].RandomLtN(order_, &b_vec[i]);
    }

    // Commitment P = <a,G> + <b, H*y_inv^i> + <a,b>Q
    yacl::math::MPInt y_inv; // Challenge related factor
    y_inv.RandomLtN(order_, &y_inv);
    YACL_ENFORCE(!y_inv.IsZero(), "y_inv challenge cannot be zero");

    std::vector<yacl::math::MPInt> y_inv_pows = ExpIterVector(y_inv, n, curve_);
    std::vector<yacl::crypto::EcPoint> H_prime_vec(n); // H' = H * y_inv^i
    for(size_t i=0; i<n; ++i) {
        H_prime_vec[i] = curve_->Mul(H_vec[i], y_inv_pows[i]);
    }

    yacl::math::MPInt c = InnerProduct(a_vec, b_vec, curve_); // <a,b>

    std::vector<yacl::math::MPInt> P_scalars; P_scalars.reserve(2*n + 1);
    std::vector<yacl::crypto::EcPoint> P_points; P_points.reserve(2*n + 1);
    for(size_t i=0; i<n; ++i) { P_scalars.push_back(a_vec[i]); P_points.push_back(G_vec[i]); }
    for(size_t i=0; i<n; ++i) { P_scalars.push_back(b_vec[i]); P_points.push_back(H_prime_vec[i]); } // Use H' here
    P_scalars.push_back(c); P_points.push_back(Q);
    yacl::crypto::EcPoint P = MultiScalarMul(curve_, P_scalars, P_points);

    // 2. Prover: Create proof
    SimpleTranscript prover_transcript(transcript_label);
    // Factors for IPP Create: G=1, H=y^-i
    std::vector<yacl::math::MPInt> ipp_G_factors(n, one);
    std::vector<yacl::math::MPInt> ipp_H_factors = y_inv_pows; // H factors are y^-i

    InnerProductProof proof;
    ASSERT_NO_THROW({
      proof = InnerProductProof::Create(
          &prover_transcript, curve_, Q,
          ipp_G_factors, ipp_H_factors, // Pass factors
          G_vec, H_vec, // Pass original G, H bases
          a_vec, b_vec); // Pass witnesses
    });


    // 3. Verifier: Verify proof
    SimpleTranscript verifier_transcript(transcript_label);
    bool result = false;
    ASSERT_NO_THROW({
      result = proof.Verify(
          &verifier_transcript, curve_,
          ipp_G_factors, ipp_H_factors, // Verifier needs factors too
          P, Q,
          G_vec, H_vec); // Verifier uses original G, H bases
    });
    ASSERT_TRUE(result) << "IPP verification failed for n=" << n;

    // 4. Test Serialization/Deserialization
    yacl::Buffer proof_bytes;
    ASSERT_NO_THROW({ proof_bytes = proof.ToBytes(curve_); });
    ASSERT_NE(proof_bytes.size(), 0);

    InnerProductProof deserialized_proof;
    ASSERT_NO_THROW({ deserialized_proof = InnerProductProof::FromBytes(proof_bytes, curve_); });

    // Verify deserialized proof
    SimpleTranscript verifier_transcript2(transcript_label);
    bool result2 = false;
    ASSERT_NO_THROW({
      result2 = deserialized_proof.Verify(
          &verifier_transcript2, curve_,
          ipp_G_factors, ipp_H_factors, P, Q, G_vec, H_vec);
    });
    ASSERT_TRUE(result2) << "IPP verification failed after serde for n=" << n;
  }

  std::shared_ptr<yacl::crypto::EcGroup> curve_;
  yacl::math::MPInt order_;
};

// Test cases matching Rust tests
TEST_F(InnerProductProofTest, MakeIPP1) {
  TestHelperCreate(1);
}

TEST_F(InnerProductProofTest, MakeIPP2) {
  TestHelperCreate(2);
}

TEST_F(InnerProductProofTest, MakeIPP4) {
  TestHelperCreate(4);
}

TEST_F(InnerProductProofTest, MakeIPP32) {
  TestHelperCreate(32);
}

TEST_F(InnerProductProofTest, MakeIPP64) {
  TestHelperCreate(64);
}


} // namespace
} // namespace examples::zkp

// Boilerplate main function for Google Test
int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}