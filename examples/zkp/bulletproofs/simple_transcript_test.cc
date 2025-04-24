#include "zkp/bulletproofs/simple_transcript.h"

#include "gtest/gtest.h"
#include "yacl/crypto/ecc/openssl/openssl_group.h"
#include "yacl/crypto/ecc/curve_meta.h"
#include "yacl/math/mpint/mp_int.h"
#include "yacl/base/exception.h"
#include <string>

namespace examples::zkp {

using yacl::crypto::EcGroup;
using yacl::crypto::EcPoint;
using yacl::math::MPInt;

class SimpleTranscriptTest : public ::testing::Test {
 protected:
  void SetUp() override {
    curve_ = yacl::crypto::openssl::OpensslGroup::Create(
        yacl::crypto::GetCurveMetaByName("secp256k1"));
    ASSERT_NE(curve_, nullptr);
  }

  std::shared_ptr<EcGroup> curve_;
};

// Test Initialization and Basic Absorb/Challenge
TEST_F(SimpleTranscriptTest, InitAndAbsorb) {
  SimpleTranscript t1(yacl::ByteContainerView("test_label_1"));
  SimpleTranscript t2(yacl::ByteContainerView("test_label_2"));
  SimpleTranscript t3(yacl::ByteContainerView("test_label_1")); // Same as t1

  // Absorb same data into t1 and t3
  std::string data1 = "some data";
  t1.Absorb(yacl::ByteContainerView("data_label"), yacl::ByteContainerView(data1));
  t3.Absorb(yacl::ByteContainerView("data_label"), yacl::ByteContainerView(data1));

  // Absorb different data into t2
  std::string data2 = "other data";
  t2.Absorb(yacl::ByteContainerView("data_label"), yacl::ByteContainerView(data2));

  // Get challenges
  MPInt order = curve_->GetOrder();
  MPInt c1 = t1.ChallengeMPInt(yacl::ByteContainerView("challenge"), order);
  MPInt c2 = t2.ChallengeMPInt(yacl::ByteContainerView("challenge"), order);
  MPInt c3 = t3.ChallengeMPInt(yacl::ByteContainerView("challenge"), order);

  // t1 and t3 should produce the same challenge
  EXPECT_EQ(c1, c3);
  // t1 and t2 should produce different challenges
  EXPECT_NE(c1, c2);
}

// Test Absorbing Scalars
TEST_F(SimpleTranscriptTest, AbsorbScalar) {
  SimpleTranscript t1(yacl::ByteContainerView("scalar_test"));
  SimpleTranscript t2(yacl::ByteContainerView("scalar_test"));

  MPInt s1, s2;
  s1.Set(1234567890);
  s2.Set(987654321);

  t1.AbsorbScalar(yacl::ByteContainerView("scalar1"), s1);
  t2.AbsorbScalar(yacl::ByteContainerView("scalar1"), s2);

  MPInt order = curve_->GetOrder();
  MPInt c1 = t1.ChallengeMPInt(yacl::ByteContainerView("challenge"), order);
  MPInt c2 = t2.ChallengeMPInt(yacl::ByteContainerView("challenge"), order);

  EXPECT_NE(c1, c2);
}

// Test Absorbing EC Points
TEST_F(SimpleTranscriptTest, AbsorbEcPoint) {
  SimpleTranscript t1(yacl::ByteContainerView("point_test"));
  SimpleTranscript t2(yacl::ByteContainerView("point_test"));

  EcPoint p1 = curve_->GetGenerator();
  EcPoint p2 = curve_->MulBase(MPInt(2)); // Different point

  t1.AbsorbEcPoint(curve_, yacl::ByteContainerView("point1"), p1);
  t2.AbsorbEcPoint(curve_, yacl::ByteContainerView("point1"), p2);

  MPInt order = curve_->GetOrder();
  MPInt c1 = t1.ChallengeMPInt(yacl::ByteContainerView("challenge"), order);
  MPInt c2 = t2.ChallengeMPInt(yacl::ByteContainerView("challenge"), order);

  EXPECT_NE(c1, c2);
}

// Test ValidateAndAbsorbEcPoint
TEST_F(SimpleTranscriptTest, ValidateAndAbsorbEcPoint) {
  SimpleTranscript t1(yacl::ByteContainerView("validate_point_test"));

  EcPoint valid_point = curve_->GetGenerator();
  EcPoint identity_point = curve_->Add(valid_point, curve_->Negate(valid_point)); // Should be identity
  ASSERT_TRUE(curve_->IsInfinity(identity_point));

  // Absorbing a valid point should succeed
  EXPECT_NO_THROW(t1.ValidateAndAbsorbEcPoint(curve_, yacl::ByteContainerView("valid_pt"), valid_point));

  // Absorbing the identity point should throw
  EXPECT_THROW(t1.ValidateAndAbsorbEcPoint(curve_, yacl::ByteContainerView("invalid_pt"), identity_point),
               yacl::Exception);
}

// Test Domain Separation Methods
TEST_F(SimpleTranscriptTest, DomainSeparation) {
  SimpleTranscript t_base(yacl::ByteContainerView("base"));
  SimpleTranscript t_range(yacl::ByteContainerView("base"));
  SimpleTranscript t_ipp(yacl::ByteContainerView("base"));

  t_range.RangeProofDomainSep(64, 1);
  t_ipp.InnerProductDomainSep(64);

  MPInt order = curve_->GetOrder();
  MPInt c_base = t_base.ChallengeMPInt(yacl::ByteContainerView("challenge"), order);
  MPInt c_range = t_range.ChallengeMPInt(yacl::ByteContainerView("challenge"), order);
  MPInt c_ipp = t_ipp.ChallengeMPInt(yacl::ByteContainerView("challenge"), order);

  // Different domain separators should lead to different states/challenges
  EXPECT_NE(c_base, c_range);
  EXPECT_NE(c_base, c_ipp);
  EXPECT_NE(c_range, c_ipp);
}

// Test SqueezeBytes and its effect on state
TEST_F(SimpleTranscriptTest, SqueezeBytes) {
  SimpleTranscript t1(yacl::ByteContainerView("squeeze_test"));

  // Initial challenge
  MPInt order = curve_->GetOrder();
  MPInt c_before = t1.ChallengeMPInt(yacl::ByteContainerView("c1"), order);

  // Squeeze some bytes
  size_t num_bytes_to_squeeze = 32;
  yacl::Buffer squeezed1 = t1.SqueezeBytes(yacl::ByteContainerView("squeeze1"), num_bytes_to_squeeze);
  EXPECT_EQ(squeezed1.size(), num_bytes_to_squeeze);

  // Challenge after squeezing should be different because state changed
  MPInt c_after1 = t1.ChallengeMPInt(yacl::ByteContainerView("c2"), order);
  EXPECT_NE(c_before, c_after1);

  // Squeezing again with a different label
   yacl::Buffer squeezed2 = t1.SqueezeBytes(yacl::ByteContainerView("squeeze2"), 16);
   EXPECT_EQ(squeezed2.size(), 16);

  // Challenge after second squeeze
  MPInt c_after2 = t1.ChallengeMPInt(yacl::ByteContainerView("c3"), order);
  EXPECT_NE(c_after1, c_after2);
  EXPECT_NE(c_before, c_after2);
}


} // namespace examples::zkp 