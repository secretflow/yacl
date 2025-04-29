#include "zkp/bulletproofs/inner_product_proof.h"

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <tuple> // Needed for std::tuple

#include "yacl/crypto/hash/hash_utils.h"
#include "zkp/bulletproofs/generators.h"
#include "zkp/bulletproofs/simple_transcript.h" // Include transcript
#include "zkp/bulletproofs/util.h"

// Forward declare FloorLog2 if it's not in a header included here
// Or include the header where it's defined (e.g., "zkp/bulletproofs/util.h")
// Assuming it's in util.h based on previous context
// size_t FloorLog2(size_t x);


namespace examples::zkp {
namespace {

class InnerProductProofTest : public ::testing::Test {
 protected:
  void SetUp() override {
    try {
      // Set up the curve
      // Using secp256k1 as specified
      curve_ = yacl::crypto::EcGroupFactory::Instance().Create(
       "secp256k1",
        yacl::ArgLib = "openssl"); // Or try "ipp" if openssl causes issues
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
    // Use the correct way to get vectors from BulletproofGensShare
    G = share.G(n);
    H = share.H(n);

    // Generate a random Q point using HashToCurve for better distribution
    std::string q_seed = "inner_product_Q_seed";
    yacl::crypto::EcPoint Q = curve_->HashToCurve(yacl::crypto::HashToCurveStrategy::Autonomous,
                                            yacl::ByteContainerView(q_seed));


    // Generate random vectors a and b
    std::vector<yacl::math::MPInt> a, b;
    a.reserve(n);
    b.reserve(n);
    for (size_t i = 0; i < n; ++i) {
      MPInt a_i;
      MPInt::RandomMonicExactBits(256, &a_i);
      a.push_back(a_i); // Use curve's random scalar method
      MPInt b_i;
      MPInt::RandomMonicExactBits(256, &b_i);
      b.push_back(b_i);
    }

    // Compute the inner product c = <a,b> (integer result)
    yacl::math::MPInt c_int = InnerProduct(a, b);
    // Reduce c for use as a scalar if needed (depends on how Q is used)
    yacl::math::MPInt c = c_int.Mod(curve_->GetOrder());


    // --- Setup for Original Commitment P ---
    // This P is the commitment the Verifier receives.
    // The standard IPP commitment is P = <a,G> + <b,H> + <a,b>Q
    // where a, b are the original vectors.

    std::vector<yacl::math::MPInt> P_scalars;
    std::vector<yacl::crypto::EcPoint> P_points;
    P_scalars.reserve(n + n + 1);
    P_points.reserve(n + n + 1);

    // <a,G> terms
    for (size_t i = 0; i < n; ++i) {
      P_scalars.push_back(a[i]);
      P_points.push_back(G[i]);
    }

    // <b,H> terms
    for (size_t i = 0; i < n; ++i) {
      P_scalars.push_back(b[i]);
      P_points.push_back(H[i]);
    }

    // <a,b>Q term (using reduced c)
    P_scalars.push_back(c);
    P_points.push_back(Q);

    // Compute P
    yacl::crypto::EcPoint P = MultiScalarMul(curve_, P_scalars, P_points);

    // --- Factors for Create/Verify (Often just 1 for basic IPP) ---
    // The reference IPP often assumes factors are 1 unless embedded in a larger protocol.
    // Let's use 1s for simplicity, matching the standard IPP formulation.
    std::vector<yacl::math::MPInt> G_factors(n, yacl::math::MPInt(1));
    std::vector<yacl::math::MPInt> H_factors(n, yacl::math::MPInt(1));

    // --- Create Proof ---
    SimpleTranscript prover_transcript("innerproducttest");
    InnerProductProof proof = InnerProductProof::Create(
        &prover_transcript,
        curve_,
        Q,         // Pass the auxiliary point
        G_factors, // Pass factors (all 1s)
        H_factors, // Pass factors (all 1s)
        G,         // Pass original generators
        H,         // Pass original generators
        a,         // Pass original vectors
        b);

    // --- Verify Proof ---
    SimpleTranscript verifier_transcript("innerproducttest");

    bool result = proof.Verify(
        n,
        &verifier_transcript,
        curve_,
        G_factors, // Pass same factors
        H_factors, // Pass same factors
        P,         // Pass the commitment P calculated above
        Q,         // Pass the auxiliary point
        G,         // Pass original generators
        H);        // Pass original generators

    EXPECT_TRUE(result) << "Verification failed for n=" << n;

    // --- Test Serialization/Deserialization (only if verification passes) ---
    if (result) {
      yacl::Buffer proof_bytes = proof.ToBytes(curve_);
      InnerProductProof deserialized_proof =
          InnerProductProof::FromBytes(proof_bytes, curve_);

      // Verify the deserialized proof
      SimpleTranscript verify2_transcript("innerproducttest");
      bool result2 = deserialized_proof.Verify(
          n,
          &verify2_transcript, // Use a fresh transcript
          curve_,
          G_factors,
          H_factors,
          P,
          Q,
          G,
          H);

      EXPECT_TRUE(result2) << "Verification failed after deserialization for n=" << n;
    }
  }

  std::shared_ptr<yacl::crypto::EcGroup> curve_;
  bool ec_available_ = false;
};

// --- Basic Test ---
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

  // 1*2 + 2*3 + 3*4 + 4*5 = 2 + 6 + 12 + 20 = 40
  EXPECT_EQ(InnerProduct(a, b), yacl::math::MPInt(40));
}

// --- New Targeted Tests ---

// Test MultiScalarMul with a simple known case
TEST_F(InnerProductProofTest, TestMultiScalarMulSimple) {
  if (!ec_available_) {
    GTEST_SKIP() << "Skipping test because EC operations are not available";
  }

  yacl::crypto::EcPoint G0 = curve_->GetGenerator();
  // Generate G1 deterministically for reproducibility
  yacl::crypto::EcPoint G1 = curve_->HashToCurve(yacl::crypto::HashToCurveStrategy::Autonomous, "G1_seed");

  yacl::math::MPInt one(1);
  yacl::math::MPInt two(2);

  std::vector<yacl::math::MPInt> scalars = {one, two};
  std::vector<yacl::crypto::EcPoint> points = {G0, G1};

  // Calculate expected result: 1*G0 + 2*G1
  yacl::crypto::EcPoint term1 = curve_->Mul(G0, one);
  yacl::crypto::EcPoint term2 = curve_->Mul(G1, two);
  yacl::crypto::EcPoint expected_result = curve_->Add(term1, term2);

  // Calculate using MultiScalarMul
  yacl::crypto::EcPoint actual_result = MultiScalarMul(curve_, scalars, points);

  EXPECT_TRUE(curve_->PointEqual(actual_result, expected_result))
      << "MultiScalarMul(1*G0 + 2*G1) failed. Expected "
      << curve_->GetAffinePoint(expected_result) << ", got "
      << curve_->GetAffinePoint(actual_result);
}

TEST_F(InnerProductProofTest, TestBasePointMulByOne) {
    if (!ec_available_) {
        GTEST_SKIP();
    }
    yacl::crypto::EcPoint G0 = curve_->GetGenerator();
    yacl::crypto::EcPoint G1 = curve_->HashToCurve(yacl::crypto::HashToCurveStrategy::Autonomous, "G1_seed");
    yacl::math::MPInt one(1);
    yacl::crypto::EcPoint G0_times_1 = curve_->Mul(G0, one);

    EXPECT_FALSE(curve_->IsInfinity(G0_times_1)) << "Mul(G0, 1) resulted in infinity!";
    // EXPECT_TRUE(curve_->PointEqual(G0_times_1, G0)) << "Mul(G0, 1) is not equal to G0!";
    // Also check serialization length
    EXPECT_EQ(curve_->SerializePoint(G0_times_1), curve_->SerializePoint(G0))
        << "Serialization length of Mul(G0, 1) is incorrect.";
}


// --- Original IPP Tests ---

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