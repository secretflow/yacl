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

#include "fmt/ranges.h"
#include "gtest/gtest.h"

#include "yacl/crypto/base/ecc/ecc_spi.h"

namespace yacl::crypto::test {

TEST(CurveFactoryTest, FactoryWorks) {
  // test list lib
  EXPECT_TRUE(EcGroupFactory::ListEcLibraries("not_exist").empty());

  auto all = EcGroupFactory::ListEcLibraries();
  ASSERT_TRUE(std::find(all.begin(), all.end(), "toy") != all.end())
      << fmt::format("{}", all);
  ASSERT_TRUE(std::find(all.begin(), all.end(), "openssl") != all.end());

  all = EcGroupFactory::ListEcLibraries("sm2");
  ASSERT_TRUE(std::find(all.begin(), all.end(), "toy") != all.end());
  ASSERT_TRUE(std::find(all.begin(), all.end(), "openssl") != all.end());

  // test create curve
  auto c1 = EcGroupFactory::Create("sm2", "toy");
  EXPECT_STRCASEEQ(c1->GetLibraryName().c_str(), "Toy");

  // the openssl's performance is better, so the factory choose openssl
  auto c2 = EcGroupFactory::Create("sm2");
  EXPECT_STRCASEEQ(c2->GetLibraryName().c_str(), "openssl");
}

// test
class EcCurveTest : public ::testing::TestWithParam<std::string> {
 protected:
  std::unique_ptr<EcGroup> ref_;  // We treat this lib/curve as a reference
  std::unique_ptr<EcGroup> ec_;   // This lib/curve we should to test

  void TestArithmeticWorks() {
    EXPECT_STRCASEEQ(ec_->GetLibraryName().c_str(), GetParam().c_str());
    EXPECT_EQ(ref_->GetCofactor(), ec_->GetCofactor());
    EXPECT_EQ(ref_->GetField(), ec_->GetField());
    EXPECT_EQ(ref_->GetOrder(), ec_->GetOrder());
    EXPECT_EQ(ref_->GetAffinePoint(ref_->GetGenerator()),
              ec_->GetAffinePoint(ec_->GetGenerator()));

    // scalar * G
    auto ref1 = ref_->MulBase(0_mp);
    auto ec1 = ec_->MulBase(0_mp);
    EXPECT_TRUE(ec_->IsInCurveGroup(ec1));
    EXPECT_TRUE(ec_->IsInfinity(ec1));

    auto s = "123456789123456789123456789"_mp;
    ref1 = ref_->MulBase(s);
    ec1 = ec_->MulBase(s);
    ASSERT_EQ(ref_->GetAffinePoint(ref1), ec_->GetAffinePoint(ec1));
    EXPECT_TRUE(ec_->IsInCurveGroup(ec1));
    EXPECT_FALSE(ec_->IsInfinity(ec1));

    // Negate
    auto ec2 = ec_->MulBase(-s);
    EXPECT_TRUE(ec_->PointEqual(ec_->Negate(ec1), ec2));

    // Add, Sub, Double
    // now: ec1 = sG; ec2 = -sG
    auto ec3 = ec_->Add(ec1, ec2);  // ec3 = 0
    EXPECT_TRUE(ec_->IsInfinity(ec3));
    EXPECT_TRUE(ec_->PointEqual(ec_->Add(ec1, ec3), ec1));
    EXPECT_TRUE(ec_->PointEqual(ec_->Add(ec2, ec3), ec2));
    ec3 = ec_->Double(ec1);  // ec3 = 2sG
    ASSERT_TRUE(ec_->PointEqual(ec_->Add(ec1, ec1), ec3));

    // Sub, Div, MulDoubleBase
    // now: ec1 = sG; ec2 = -sG; ec3 = 2sG
    ASSERT_TRUE(ec_->PointEqual(ec_->Sub(ec3, ec1), ec1));
    ASSERT_TRUE(ec_->PointEqual(ec_->Sub(ec1, ec2), ec3));
    ASSERT_TRUE(ec_->PointEqual(ec_->Div(ec3, 2_mp), ec1));
    ASSERT_TRUE(ec_->PointEqual(ec_->Div(ec3, -2_mp), ec2));
    ASSERT_TRUE(ec_->PointEqual(ec_->Div(ec1, s), ec_->GetGenerator()));
    ASSERT_TRUE(
        ec_->PointEqual(ec_->Div(ec2, s), ec_->Negate(ec_->GetGenerator())));
    ASSERT_TRUE(ec_->PointEqual(ec_->Div(ec3, s), ec_->MulBase(2_mp)));
    // ec2 * 100 + 102s * G = ec3
    ASSERT_TRUE(
        ec_->PointEqual(ec_->MulDoubleBase(100_mp, ec2, s * 102_mp), ec3));
  }

  void TestSerializeWorks() {
    auto s = 12345_mp;
    auto p1 = ec_->MulBase(s);  // p1 = sG
    auto buf = ec_->SerializePoint(p1);
    auto p2 = ec_->DeserializePoint(buf);
    ASSERT_TRUE(ec_->PointEqual(p1, p2));

    p2 = ec_->Div(p2, s);
    ec_->SerializePoint(p2, &buf);
    ASSERT_TRUE(
        ec_->PointEqual(ec_->DeserializePoint(buf), ec_->GetGenerator()));

    if (ec_->GetLibraryName() == "Toy") {
      return;  // The toy lib do not support X9.62 format
    }

    // test ANSI X9.62 format
    auto p3 = ec_->Mul(67890_mp, p1);
    buf = ec_->SerializePoint(p3, PointOctetFormat::X962Compressed);
    ASSERT_TRUE(buf.data<char>()[0] == 0x2 || buf.data<char>()[0] == 0x3)
        << fmt::format("real={:x}", buf.data<uint8_t>()[0]);
    auto p4 = ec_->DeserializePoint(buf, PointOctetFormat::X962Compressed);
    ASSERT_TRUE(ec_->PointEqual(p3, p4));

    buf = ec_->SerializePoint(p3, PointOctetFormat::X962Uncompressed);
    ASSERT_TRUE(buf.data<char>()[0] == 0x4);
    p4 = ec_->DeserializePoint(buf, PointOctetFormat::X962Uncompressed);
    ASSERT_TRUE(ec_->PointEqual(p3, p4));

    buf = ec_->SerializePoint(p3, PointOctetFormat::X962Hybrid);
    ASSERT_TRUE(buf.data<char>()[0] == 0x6 || buf.data<char>()[0] == 0x7);
    p4 = ec_->DeserializePoint(buf, PointOctetFormat::X962Hybrid);
    ASSERT_TRUE(ec_->PointEqual(p3, p4));

    // test zero
    auto p5 = ec_->Mul(0_mp, p3);
    ASSERT_TRUE(ec_->IsInfinity(p5));
    buf = ec_->SerializePoint(p5, PointOctetFormat::X962Compressed);
    ASSERT_TRUE(buf.data<char>()[0] == 0x0);
    ASSERT_EQ(buf.size(), 1);
    auto p6 = ec_->DeserializePoint(buf, PointOctetFormat::X962Compressed);
    ASSERT_TRUE(ec_->IsInfinity(p6));
  }
};

class Sm2CurveTest : public EcCurveTest {
 protected:
  void SetUp() override {
    ref_ = EcGroupFactory::Create("sm2", "toy");
    ec_ = EcGroupFactory::Create("sm2", GetParam());
  }
};

INSTANTIATE_TEST_SUITE_P(
    Sm2Test, Sm2CurveTest,
    ::testing::ValuesIn(EcGroupFactory::ListEcLibraries("sm2")));

TEST_P(Sm2CurveTest, SpiTest) {
  EXPECT_STRCASEEQ(ec_->GetCurveName().c_str(), "sm2");
  EXPECT_EQ(ec_->GetCurveForm(), CurveForm::Weierstrass);
  EXPECT_EQ(ec_->GetFieldType(), FieldType::Prime);
  EXPECT_EQ(ec_->GetSecurityStrength(), 128);
  EXPECT_FALSE(ec_->ToString().empty());

  TestArithmeticWorks();
  TestSerializeWorks();
}

}  // namespace yacl::crypto::test
