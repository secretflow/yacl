// Copyright 2024 Ant Group Co., Ltd.
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

#include <memory>
#include <string>

#include "fmt/format.h"
#include "gtest/gtest.h"

#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/crypto/ecc/libsodium/ristretto255_group.h"
#include "yacl/utils/spi/spi_factory.h"

namespace yacl::crypto::sodium::test {

class Ristretto255Test : public ::testing::Test {
 protected:
  std::unique_ptr<EcGroup> ec_ =
      EcGroupFactory::Instance().Create("ristretto255", ArgLib = "libsodium");
};

// Test 1: Basic Creation
TEST_F(Ristretto255Test, CreateWorks) {
  ASSERT_NE(ec_, nullptr);
  EXPECT_STRCASEEQ(ec_->GetCurveName().c_str(), "ristretto255");
  EXPECT_EQ(ec_->GetLibraryName(), "libsodium");
  EXPECT_EQ(ec_->GetCofactor(), 1_mp);  // Prime-order group!
  EXPECT_EQ(ec_->GetSecurityStrength(), 127);
  EXPECT_EQ(ec_->GetCurveForm(), CurveForm::TwistedEdwards);
  EXPECT_EQ(ec_->GetFieldType(), FieldType::Prime);
  EXPECT_FALSE(ec_->ToString().empty());
}

// Test 2: Generator Point
TEST_F(Ristretto255Test, GeneratorWorks) {
  auto g = ec_->GetGenerator();
  EXPECT_TRUE(ec_->IsInCurveGroup(g));
  EXPECT_FALSE(ec_->IsInfinity(g));

  // 1 * G should equal generator
  auto g2 = ec_->MulBase(1_mp);
  EXPECT_TRUE(ec_->PointEqual(g, g2));
}

// Test 3: Identity Element
TEST_F(Ristretto255Test, InfinityWorks) {
  auto inf = ec_->MulBase(0_mp);
  EXPECT_TRUE(ec_->IsInfinity(inf));
  EXPECT_TRUE(ec_->IsInCurveGroup(inf));

  // P + 0 = P
  auto g = ec_->GetGenerator();
  auto sum = ec_->Add(g, inf);
  EXPECT_TRUE(ec_->PointEqual(sum, g));

  // 0 + P = P
  sum = ec_->Add(inf, g);
  EXPECT_TRUE(ec_->PointEqual(sum, g));

  // Copy infinity
  auto inf2 = ec_->CopyPoint(inf);
  EXPECT_TRUE(ec_->IsInfinity(inf2));
  EXPECT_TRUE(ec_->PointEqual(inf, inf2));
}

// Test 4: Addition/Subtraction
TEST_F(Ristretto255Test, ArithmeticWorks) {
  auto p1 = ec_->MulBase(123_mp);
  auto p2 = ec_->MulBase(456_mp);
  auto p3 = ec_->MulBase(579_mp);  // 123 + 456

  // Test addition
  auto sum = ec_->Add(p1, p2);
  EXPECT_TRUE(ec_->PointEqual(sum, p3));

  // Test subtraction
  auto diff = ec_->Sub(p3, p2);
  EXPECT_TRUE(ec_->PointEqual(diff, p1));

  // Test AddInplace
  auto p1_copy = ec_->CopyPoint(p1);
  ec_->AddInplace(&p1_copy, p2);
  EXPECT_TRUE(ec_->PointEqual(p1_copy, p3));

  // Test SubInplace
  auto p3_copy = ec_->CopyPoint(p3);
  ec_->SubInplace(&p3_copy, p2);
  EXPECT_TRUE(ec_->PointEqual(p3_copy, p1));
}

// Test 5: Scalar Multiplication
TEST_F(Ristretto255Test, MulWorks) {
  auto g = ec_->GetGenerator();

  // Test MulBase vs Mul(G, scalar)
  auto p1 = ec_->MulBase(100_mp);
  auto p2 = ec_->Mul(g, 100_mp);
  EXPECT_TRUE(ec_->PointEqual(p1, p2));

  // Test 2*G = G + G
  auto two_g = ec_->MulBase(2_mp);
  auto g_plus_g = ec_->Add(g, g);
  EXPECT_TRUE(ec_->PointEqual(two_g, g_plus_g));

  // Test n*G = identity (where n is the order)
  auto n = ec_->GetOrder();
  auto inf = ec_->MulBase(n);
  EXPECT_TRUE(ec_->IsInfinity(inf));

  // Test MulInplace
  auto p = ec_->CopyPoint(g);
  ec_->MulInplace(&p, 100_mp);
  EXPECT_TRUE(ec_->PointEqual(p, p1));

  // Test MulDoubleBase: s1*G + s2*P
  auto s1 = 10_mp;
  auto s2 = 20_mp;
  auto P = ec_->MulBase(5_mp);
  auto result = ec_->MulDoubleBase(s1, s2, P);
  auto expected = ec_->Add(ec_->MulBase(s1), ec_->Mul(P, s2));
  EXPECT_TRUE(ec_->PointEqual(result, expected));
}

// Test 6: Double
TEST_F(Ristretto255Test, DoubleWorks) {
  auto g = ec_->GetGenerator();
  auto double_g = ec_->Double(g);
  auto two_g = ec_->MulBase(2_mp);
  EXPECT_TRUE(ec_->PointEqual(double_g, two_g));

  // Test DoubleInplace
  auto p = ec_->CopyPoint(g);
  ec_->DoubleInplace(&p);
  EXPECT_TRUE(ec_->PointEqual(p, two_g));
}

// Test 7: Negation
TEST_F(Ristretto255Test, NegateWorks) {
  auto p = ec_->MulBase(1234_mp);
  auto neg_p = ec_->Negate(p);

  // P + (-P) = 0
  auto sum = ec_->Add(p, neg_p);
  EXPECT_TRUE(ec_->IsInfinity(sum));

  // -P should equal (-scalar)*G
  auto neg_p2 = ec_->MulBase(-1234_mp);
  EXPECT_TRUE(ec_->PointEqual(neg_p, neg_p2));

  // Test NegateInplace
  auto p_copy = ec_->CopyPoint(p);
  ec_->NegateInplace(&p_copy);
  EXPECT_TRUE(ec_->PointEqual(p_copy, neg_p));

  // Negate identity should be identity
  auto inf = ec_->MulBase(0_mp);
  auto neg_inf = ec_->Negate(inf);
  EXPECT_TRUE(ec_->IsInfinity(neg_inf));
}

// Test 8: Serialization
TEST_F(Ristretto255Test, SerializeWorks) {
  auto p1 = ec_->MulBase(999_mp);

  // Test SerializePoint
  auto buf = ec_->SerializePoint(p1);
  EXPECT_EQ(buf.size(), 32u);  // Ristretto255 uses 32-byte encoding

  // Test DeserializePoint
  auto p2 = ec_->DeserializePoint(buf);
  EXPECT_TRUE(ec_->PointEqual(p1, p2));

  // Test GetSerializeLength
  EXPECT_EQ(ec_->GetSerializeLength(PointOctetFormat::Autonomous), 32u);

  // Serialize identity
  auto inf = ec_->MulBase(0_mp);
  auto inf_buf = ec_->SerializePoint(inf);
  EXPECT_EQ(inf_buf.size(), 32u);

  // All zeros should be identity
  std::vector<uint8_t> zero_bytes(32, 0);
  auto inf2 = ec_->DeserializePoint(zero_bytes);
  EXPECT_TRUE(ec_->IsInfinity(inf2));
}

// Test 9: Hash-to-Curve
TEST_F(Ristretto255Test, HashToCurveWorks) {
  std::string input = "test input for hash to curve";
  std::string dst = "YACL_Ristretto255_Test";

  auto p1 = ec_->HashToCurve(HashToCurveStrategy::SHA512_R255_RO_, input, dst);

  EXPECT_TRUE(ec_->IsInCurveGroup(p1));
  EXPECT_FALSE(ec_->IsInfinity(p1));

  // Same input should produce same point (deterministic)
  auto p2 = ec_->HashToCurve(HashToCurveStrategy::SHA512_R255_RO_, input, dst);
  EXPECT_TRUE(ec_->PointEqual(p1, p2));

  // Different input should produce different point
  auto p3 = ec_->HashToCurve(HashToCurveStrategy::SHA512_R255_RO_,
                             "different input", dst);
  EXPECT_FALSE(ec_->PointEqual(p1, p3));

  // Different DST should produce different point
  auto p4 = ec_->HashToCurve(HashToCurveStrategy::SHA512_R255_RO_, input,
                             "Different_DST_16bytes");
  EXPECT_FALSE(ec_->PointEqual(p1, p4));
}

// Test 10: Hash-to-Scalar
TEST_F(Ristretto255Test, HashToScalarWorks) {
  std::string input = "test input for hash to scalar";
  std::string dst = "YACL_Ristretto255_Scalar_Test";

  auto s1 = ec_->HashToScalar(HashToCurveStrategy::Ristretto255_SHA512_, input, dst);

  // Scalar should be in valid range [0, n)
  EXPECT_TRUE(s1.IsPositive() || s1.IsZero());
  EXPECT_TRUE(s1 < ec_->GetOrder());

  // Same input should produce same scalar (deterministic)
  auto s2 = ec_->HashToScalar(HashToCurveStrategy::Ristretto255_SHA512_, input, dst);
  EXPECT_EQ(s1, s2);

  // Different input should produce different scalar
  auto s3 = ec_->HashToScalar(HashToCurveStrategy::Ristretto255_SHA512_,
                              "different input", dst);
  EXPECT_NE(s1, s3);
}

// Test 11: Point Equality
TEST_F(Ristretto255Test, PointEqualWorks) {
  auto p1 = ec_->MulBase(42_mp);
  auto p2 = ec_->MulBase(42_mp);
  auto p3 = ec_->MulBase(43_mp);

  EXPECT_TRUE(ec_->PointEqual(p1, p2));
  EXPECT_FALSE(ec_->PointEqual(p1, p3));

  // Identity equality
  auto inf1 = ec_->MulBase(0_mp);
  auto inf2 = ec_->MulBase(ec_->GetOrder());
  EXPECT_TRUE(ec_->PointEqual(inf1, inf2));
}

// Test 12: Large Scalar
TEST_F(Ristretto255Test, BigScalarWorks) {
  MPInt big_scalar;
  MPInt::RandomMonicExactBits(256, &big_scalar);

  auto p = ec_->MulBase(big_scalar);
  EXPECT_TRUE(ec_->IsInCurveGroup(p));
  EXPECT_FALSE(ec_->IsInfinity(p));

  // Scalar should be reduced mod n
  auto reduced_scalar = big_scalar.Mod(ec_->GetOrder());
  auto p2 = ec_->MulBase(reduced_scalar);
  EXPECT_TRUE(ec_->PointEqual(p, p2));
}

// Test 13: Copy Point
TEST_F(Ristretto255Test, CopyPointWorks) {
  auto p1 = ec_->MulBase(852_mp);
  auto p2 = ec_->CopyPoint(p1);
  EXPECT_TRUE(ec_->PointEqual(p1, p2));

  // Check is deep copy
  ec_->AddInplace(&p1, ec_->GetGenerator());
  EXPECT_FALSE(ec_->PointEqual(p1, p2));
}

// Test 14: Hash Point
TEST_F(Ristretto255Test, HashPointWorks) {
  auto p1 = ec_->MulBase(100_mp);
  auto p2 = ec_->MulBase(100_mp);
  auto p3 = ec_->MulBase(200_mp);

  // Same points should have same hash
  EXPECT_EQ(ec_->HashPoint(p1), ec_->HashPoint(p2));

  // Different points should (very likely) have different hash
  EXPECT_NE(ec_->HashPoint(p1), ec_->HashPoint(p3));
}

// Test 15: Affine Point
TEST_F(Ristretto255Test, AffinePointWorks) {
  auto p = ec_->MulBase(12345_mp);
  auto ap = ec_->GetAffinePoint(p);

  // For Ristretto255, the encoding is returned as "x-coordinate"
  // Verify we can get some representation
  EXPECT_FALSE(ap.x.IsZero() && ap.y.IsZero());
}

// Test 16: IsInCurveGroup validation
TEST_F(Ristretto255Test, ValidationWorks) {
  // Valid point
  auto p = ec_->MulBase(42_mp);
  EXPECT_TRUE(ec_->IsInCurveGroup(p));

  // Identity is valid
  auto inf = ec_->MulBase(0_mp);
  EXPECT_TRUE(ec_->IsInCurveGroup(inf));

  // Serialized and deserialized point should be valid
  auto buf = ec_->SerializePoint(p);
  auto p2 = ec_->DeserializePoint(buf);
  EXPECT_TRUE(ec_->IsInCurveGroup(p2));
}

// Test 17: Standard Test Vectors
// Test vectors from https://ristretto.group/test_vectors/ristretto255.html
TEST_F(Ristretto255Test, StandardVectors) {
  // Basepoint encoding (1*G)
  auto g = ec_->GetGenerator();
  auto buf = ec_->SerializePoint(g);

  // The canonical encoding of the basepoint
  // e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76
  std::vector<uint8_t> expected_g = {
      0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71,
      0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00, 0x51, 0x5f,
      0x58, 0xe3, 0x0b, 0x6a, 0xa5, 0x82, 0xdd, 0x8d,
      0xb6, 0xa6, 0x59, 0x45, 0xe0, 0x8d, 0x2d, 0x76
  };
  EXPECT_EQ(buf.size(), expected_g.size());
  EXPECT_EQ(std::memcmp(buf.data(), expected_g.data(), 32), 0)
      << "Generator encoding mismatch";

  // 0*G should be all zeros (identity)
  auto inf = ec_->MulBase(0_mp);
  auto inf_buf = ec_->SerializePoint(inf);
  for (size_t i = 0; i < 32; ++i) {
    EXPECT_EQ(inf_buf.data<uint8_t>()[i], 0) << "Identity should be all zeros";
  }
}

}  // namespace yacl::crypto::sodium::test
