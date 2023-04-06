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

#include <random>

#include "fmt/ranges.h"
#include "gtest/gtest.h"

#include "yacl/crypto/base/ecc/ecc_spi.h"
#include "yacl/utils/parallel.h"

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
  std::unique_ptr<EcGroup> ec_;  // This lib/curve we should to test

  void RunAllTests() {
    fmt::print("Begin to test curve {} from {} lib\n", ec_->GetCurveName(),
               ec_->GetLibraryName());

    TestArithmeticWorks();
    TestMulIsAdd();
    TestSerializeWorks();
    TestHashPointWorks();
    TestStorePointsInMapWorks();
    MultiThreadWorks();
  }

  void TestArithmeticWorks() {
    EXPECT_STRCASEEQ(ec_->GetLibraryName().c_str(), GetParam().c_str());

    // Inf = 0 * G
    const auto p0 = ec_->MulBase(0_mp);
    EXPECT_TRUE(ec_->IsInCurveGroup(p0));
    EXPECT_TRUE(ec_->IsInfinity(p0));
    // s * G
    auto s = "123456789123456789123456789"_mp;
    const auto p1 = ec_->MulBase(s);
    EXPECT_TRUE(ec_->IsInCurveGroup(p1));
    EXPECT_FALSE(ec_->IsInfinity(p1));

    // Negate
    const auto p2 = ec_->MulBase(-s);
    EXPECT_TRUE(ec_->PointEqual(ec_->Negate(p1), p2));
    // NegateInplace
    // now: p1 = sG; p2 = -sG
    auto pt = ec_->MulBase(s);
    ec_->NegateInplace(&pt);
    ASSERT_TRUE(ec_->PointEqual(pt, p2));
    ec_->NegateInplace(&pt);
    ASSERT_TRUE(ec_->PointEqual(pt, p1));

    // Add, Sub, Double
    // now: p1 = sG; p2 = -sG
    auto p3 = ec_->Add(p1, p2);  // p3 = 0
    EXPECT_TRUE(ec_->IsInfinity(p3));
    EXPECT_TRUE(ec_->PointEqual(ec_->Add(p1, p3), p1));
    EXPECT_TRUE(ec_->PointEqual(ec_->Add(p2, p3), p2));
    p3 = ec_->Double(p1);  // p3 = 2sG
    ASSERT_TRUE(ec_->PointEqual(ec_->Add(p1, p1), p3));
    // AddInplace
    // now: pt = p1 = sG; p2 = -sG; p3 = 2sG
    ec_->AddInplace(&pt, pt);  // pt = 2sG
    ASSERT_TRUE(ec_->PointEqual(pt, p3));
    ec_->AddInplace(&pt, p2);  // pt = sG
    ASSERT_TRUE(ec_->PointEqual(pt, p1));
    // SubInplace
    ec_->SubInplace(&pt, p2);  // pt = 2sG
    ASSERT_TRUE(ec_->PointEqual(pt, p3));
    ec_->SubInplace(&pt, p1);  // pt = sG
    ASSERT_TRUE(ec_->PointEqual(pt, p1));
    // DoubleInplace
    ec_->DoubleInplace(&pt);  // pt = 2sG
    ASSERT_TRUE(ec_->PointEqual(pt, p3));
    ec_->DoubleInplace(&pt);  // pt = 4sG
    ASSERT_FALSE(ec_->PointEqual(pt, p3));
    ec_->AddInplace(&pt, ec_->Double(p2));  // pt = 2sG
    ASSERT_TRUE(ec_->PointEqual(pt, p3));

    // Sub, Div, MulDoubleBase
    // now: p1 = sG; p2 = -sG; pt = p3 = 2sG
    ASSERT_TRUE(ec_->PointEqual(ec_->Sub(p3, p1), p1));
    ASSERT_TRUE(ec_->PointEqual(ec_->Sub(p1, p2), p3));
    ASSERT_TRUE(ec_->PointEqual(ec_->Div(p3, 2_mp), p1));
    ASSERT_TRUE(ec_->PointEqual(ec_->Div(p3, -2_mp), p2));
    ASSERT_TRUE(ec_->PointEqual(ec_->Div(p1, s), ec_->GetGenerator()));
    ASSERT_TRUE(
        ec_->PointEqual(ec_->Div(p2, s), ec_->Negate(ec_->GetGenerator())));
    ASSERT_TRUE(ec_->PointEqual(ec_->Div(p3, s), ec_->MulBase(2_mp)));
    // p2 * 100 + 102s * G = p3
    ASSERT_TRUE(
        ec_->PointEqual(ec_->MulDoubleBase(102_mp * s, 100_mp, p2), p3));
    // DivInplace
    ec_->DivInplace(&pt, 2_mp);  // pt = sG
    ASSERT_TRUE(ec_->PointEqual(pt, p1));
  }

  void TestMulIsAdd() {
    auto p = ec_->MulBase(-101_mp);
    for (int i = -100; i < 100; ++i) {
      ec_->AddInplace(&p, ec_->GetGenerator());
      ASSERT_TRUE(ec_->PointEqual(p, ec_->MulBase(MPInt(i))));
    }
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
    auto p3 = ec_->Mul(p1, 67890_mp);
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
    auto p5 = ec_->Mul(p3, 0_mp);
    ASSERT_TRUE(ec_->IsInfinity(p5));
    buf = ec_->SerializePoint(p5, PointOctetFormat::X962Compressed);
    ASSERT_TRUE(buf.data<char>()[0] == 0x0);
    ASSERT_EQ(buf.size(), 1);
    auto p6 = ec_->DeserializePoint(buf, PointOctetFormat::X962Compressed);
    ASSERT_TRUE(ec_->IsInfinity(p6));
  }

  void TestHashPointWorks() {
    std::map<size_t, int> hit_table;
    auto p = ec_->MulBase(0_mp);
    int ts = 1 << 15;
    for (int i = 0; i < ts; ++i) {
      auto h = ec_->HashPoint(p);
      ++hit_table[h];
      ASSERT_EQ(hit_table[h], 1);
      ec_->AddInplace(&p, ec_->GetGenerator());
    }
    ASSERT_EQ(hit_table.size(), ts);

    p = ec_->MulBase(MPInt(-ts));
    for (int i = 0; i < ts; ++i) {
      auto h = ec_->HashPoint(p);
      ++hit_table[h];
      ASSERT_EQ(hit_table[h], 1) << fmt::format("i={}", i);
      ec_->AddInplace(&p, ec_->GetGenerator());
    }
    ASSERT_EQ(hit_table.size(), ts * 2);

    // same point should have same hash value
    for (int i = 0; i < ts; ++i) {
      auto h = ec_->HashPoint(p);
      ++hit_table[h];
      ASSERT_EQ(hit_table[h], 2);
      ec_->AddInplace(&p, ec_->GetGenerator());
    }
    ASSERT_EQ(hit_table.size(), ts * 2);
  }

  void TestStorePointsInMapWorks() {
    auto hash = [&](const EcPoint &p) { return ec_->HashPoint(p); };
    auto equal = [&](const EcPoint &p1, const EcPoint &p2) {
      return ec_->PointEqual(p1, p2);
    };

    int numel = 500;
    std::unordered_map<EcPoint, int, decltype(hash), decltype(equal)>
        points_map(numel, hash, equal);
    auto p = ec_->GetGenerator();
    for (int i = 1; i < numel; ++i) {
      p = ec_->Double(p);
      points_map[p] = i;
      if (i % 13 == 0) {
        auto tmp = ec_->MulBase(1_mp << i);
        ASSERT_TRUE(ec_->PointEqual(p, tmp));
        ASSERT_EQ(hash(p), hash(tmp));
      }
    }
    ASSERT_EQ(points_map.size(), numel - 1);
  }

  void MultiThreadWorks() {
    constexpr int64_t ts = 1 << 16;
    std::array<EcPoint, ts> buf;
    auto g = ec_->GetGenerator();
    yacl::parallel_for(0, ts, 1, [&](int64_t beg, int64_t end) {
      auto point = ec_->MulBase(MPInt(beg));
      buf[beg] = point;
      for (int64_t i = beg + 1; i < end; ++i) {
        point = ec_->Add(point, g);
        buf[i] = point;
      }
    });

    for (int64_t i = 1; i < ts; ++i) {
      ASSERT_TRUE(ec_->PointEqual(ec_->Add(buf[i - 1], g), buf[i]));
    }
  }
};

class Sm2CurveTest : public EcCurveTest {
 protected:
  void SetUp() override { ec_ = EcGroupFactory::Create("sm2", GetParam()); }
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

  std::unique_ptr<EcGroup> ref_;
  ref_ = EcGroupFactory::Create("sm2", "toy");
  // meta test
  EXPECT_EQ(ref_->GetCofactor(), ec_->GetCofactor());
  EXPECT_EQ(ref_->GetField(), ec_->GetField());
  EXPECT_EQ(ref_->GetOrder(), ec_->GetOrder());
  EXPECT_EQ(ref_->GetAffinePoint(ref_->GetGenerator()),
            ec_->GetAffinePoint(ec_->GetGenerator()));

  // Run Other tests
  RunAllTests();
}

}  // namespace yacl::crypto::test
