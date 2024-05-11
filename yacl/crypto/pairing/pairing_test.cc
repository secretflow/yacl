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

#include <cstdint>

#include "fmt/ranges.h"
#include "gtest/gtest.h"

#include "yacl/crypto/pairing/factory/pairing_spi.h"
#include "yacl/utils/parallel.h"

namespace yacl::crypto {

class PairingCurveTest : public ::testing::TestWithParam<std::string> {
 protected:
  std::unique_ptr<PairingGroup> pairing_group_;
  std::shared_ptr<GroupTarget> gt_;

  void RunAllTests() {
    fmt::print("Begin to test curve {} from {} lib\n",
               pairing_group_->GetPairingName(),
               pairing_group_->GetLibraryName());

    for (const auto &ec :
         {pairing_group_->GetGroup1(), pairing_group_->GetGroup2()}) {
      TestArithmeticWorks(ec);
      TestMulIsAdd(ec);
      TestSerializeWorks(ec);
      TestHashPointWorks(ec);
      TestStorePointsInMapWorks(ec);
      MultiThreadWorks(ec);
    }
  }

  void TestArithmeticWorks(const std::shared_ptr<EcGroup> &ec) {
    EXPECT_STRCASEEQ(ec->GetLibraryName().c_str(), GetParam().c_str());

    // Inf = 0 * G
    const auto p0 = ec->MulBase(0_mp);
    EXPECT_TRUE(ec->IsInCurveGroup(p0));
    EXPECT_TRUE(ec->IsInfinity(p0));
    // s * G
    auto s = "123456789123456789123456789"_mp;
    const auto p1 = ec->MulBase(s);
    EXPECT_TRUE(ec->IsInCurveGroup(p1));
    EXPECT_FALSE(ec->IsInfinity(p1));

    // Negate
    const auto p2 = ec->MulBase(-s);
    EXPECT_TRUE(ec->PointEqual(ec->Negate(p1), p2));
    // NegateInplace
    // now: p1 = sG; p2 = -sG
    auto pt = ec->MulBase(s);
    ec->NegateInplace(&pt);
    ASSERT_TRUE(ec->PointEqual(pt, p2));
    ec->NegateInplace(&pt);
    ASSERT_TRUE(ec->PointEqual(pt, p1));

    // Add, Sub, Double
    // now: p1 = sG; p2 = -sG
    auto p3 = ec->Add(p1, p2);  // p3 = 0
    EXPECT_TRUE(ec->IsInfinity(p3));
    EXPECT_TRUE(ec->PointEqual(ec->Add(p1, p3), p1));
    EXPECT_TRUE(ec->PointEqual(ec->Add(p2, p3), p2));
    p3 = ec->Double(p1);  // p3 = 2sG
    ASSERT_TRUE(ec->PointEqual(ec->Add(p1, p1), p3));
    // AddInplace
    // now: pt = p1 = sG; p2 = -sG; p3 = 2sG
    ec->AddInplace(&pt, pt);  // pt = 2sG
    ASSERT_TRUE(ec->PointEqual(pt, p3));
    ec->AddInplace(&pt, p2);  // pt = sG
    ASSERT_TRUE(ec->PointEqual(pt, p1));
    // SubInplace
    ec->SubInplace(&pt, p2);  // pt = 2sG
    ASSERT_TRUE(ec->PointEqual(pt, p3));
    ec->SubInplace(&pt, p1);  // pt = sG
    ASSERT_TRUE(ec->PointEqual(pt, p1));
    // DoubleInplace
    ec->DoubleInplace(&pt);  // pt = 2sG
    ASSERT_TRUE(ec->PointEqual(pt, p3));
    ec->DoubleInplace(&pt);  // pt = 4sG
    ASSERT_FALSE(ec->PointEqual(pt, p3));
    ec->AddInplace(&pt, ec->Double(p2));  // pt = 2sG
    ASSERT_TRUE(ec->PointEqual(pt, p3));

    // Sub, Div, MulDoubleBase
    // now: p1 = sG; p2 = -sG; pt = p3 = 2sG
    ASSERT_TRUE(ec->PointEqual(ec->Sub(p3, p1), p1));
    ASSERT_TRUE(ec->PointEqual(ec->Sub(p1, p2), p3));
    ASSERT_TRUE(ec->PointEqual(ec->Div(p3, 2_mp), p1));
    ASSERT_TRUE(ec->PointEqual(ec->Div(p3, -2_mp), p2));
    ASSERT_TRUE(ec->PointEqual(ec->Div(p1, s), ec->GetGenerator()));
    ASSERT_TRUE(ec->PointEqual(ec->Div(p2, s), ec->Negate(ec->GetGenerator())));
    ASSERT_TRUE(ec->PointEqual(ec->Div(p3, s), ec->MulBase(2_mp)));
    // p2 * 100 + 102s * G = p3
    ASSERT_TRUE(ec->PointEqual(ec->MulDoubleBase(102_mp * s, 100_mp, p2), p3));
    // DivInplace
    ec->DivInplace(&pt, 2_mp);  // pt = sG
    ASSERT_TRUE(ec->PointEqual(pt, p1));

    // Big Scalar Test
    {
      for (int i = 0; i <= 10; i++) {
        MPInt s1;
        MPInt::RandomMonicExactBits(256, &s1);
        MPInt s2;
        MPInt::RandomMonicExactBits(256, &s2);
        auto p1 = ec->MulBase(s1);
        auto p2 = ec->Mul(ec->GetGenerator(), s2);
        auto p3 = ec->MulDoubleBase(s1, s2, ec->GetGenerator());
        ASSERT_TRUE(ec->PointEqual(p3, ec->Add(p1, p2)));
      }
      for (int i = 0; i <= 10; i++) {
        MPInt s1;
        MPInt::RandomMonicExactBits(1024, &s1);
        MPInt s2;
        MPInt::RandomMonicExactBits(1024, &s2);
        auto p1 = ec->MulBase(s1);
        auto p2 = ec->Mul(ec->GetGenerator(), s2);
        auto p3 = ec->MulDoubleBase(s1, s2, ec->GetGenerator());
        ASSERT_TRUE(ec->PointEqual(p3, ec->Add(p1, p2)));
      }
    }
  }

  void TestMulIsAdd(const std::shared_ptr<EcGroup> &ec) {
    auto p = ec->MulBase(-101_mp);
    for (int i = -100; i < 100; ++i) {
      ec->AddInplace(&p, ec->GetGenerator());
      ASSERT_TRUE(ec->PointEqual(p, ec->MulBase(MPInt(i))));
    }
  }

  void TestSerializeWorks(const std::shared_ptr<EcGroup> &ec) {
    auto s = 12345_mp;
    auto p1 = ec->MulBase(s);  // p1 = sG
    // test ZCash_BLS12_381 format
    if (absl::AsciiStrToLower(ec->GetCurveName()) == "bls12-381") {
      std::cout << "start\n";
      auto p3 = ec->Mul(p1, 67890_mp);
      auto buf = ec->SerializePoint(p3, PointOctetFormat::ZCash_BLS12_381);
      // 160 = 1010 0000, 128 = 10000 000
      ASSERT_TRUE((buf.data<uint8_t>()[0] & 160) == 160 ||
                  (buf.data<uint8_t>()[0] & 128) == 128)
          << fmt::format("real={:x}", buf.data<uint8_t>()[0]);
      auto p4 = ec->DeserializePoint(buf, PointOctetFormat::ZCash_BLS12_381);
      ASSERT_TRUE(ec->PointEqual(p3, p4));

      // test zero
      auto p5 = ec->Mul(p3, 0_mp);
      ASSERT_TRUE(ec->IsInfinity(p5));
      buf = ec->SerializePoint(p5, PointOctetFormat::ZCash_BLS12_381);
      // 192 = 1100 0000
      ASSERT_TRUE((buf.data<uint8_t>()[0] & 192) == 192);

      auto p6 = ec->DeserializePoint(buf, PointOctetFormat::ZCash_BLS12_381);
      ASSERT_TRUE(ec->IsInfinity(p6));
      return;
    }

    auto buf = ec->SerializePoint(p1);
    auto p2 = ec->DeserializePoint(buf);
    ASSERT_TRUE(ec->PointEqual(p1, p2));

    p2 = ec->Div(p2, s);
    ec->SerializePoint(p2, &buf);
    ASSERT_TRUE(ec->PointEqual(ec->DeserializePoint(buf), ec->GetGenerator()));

    // Autonomous Serialization
    auto p3 = ec->Mul(p1, 67890_mp);
    buf = ec->SerializePoint(p3);

    auto p4 = ec->DeserializePoint(buf);
    ASSERT_TRUE(ec->PointEqual(p3, p4));

    // test zero
    auto p5 = ec->Mul(p3, 0_mp);
    ASSERT_TRUE(ec->IsInfinity(p5));
    buf = ec->SerializePoint(p5);
    // 192 = 1100 0000
    // ASSERT_TRUE((buf.data<uint8_t>()[0] & 192) == 192);

    auto p6 = ec->DeserializePoint(buf);
    ASSERT_TRUE(ec->IsInfinity(p6));

    // X962Uncompressed
    auto buf2 = ec->SerializePoint(p3, PointOctetFormat::X962Uncompressed);
    ASSERT_TRUE((buf2.data<uint8_t>()[0]) == 0x4);

    auto p7 = ec->DeserializePoint(buf2, PointOctetFormat::X962Uncompressed);
    ASSERT_TRUE(ec->PointEqual(p3, p7));
    auto p7a = ec->GetAffinePoint(p7);
    MPInt x, y;
    // buf2 = 0x04||x||y |x|=|y|=buf2.size() - 1) / 2 with little endian
    // x: 1 to buf2.size() - 1) / 2 + 1
    // y: buf2.size() - 1) / 2 + 1 to end
    ASSERT_TRUE((buf2.size() - 1) % 2 == 0);
    auto len = (buf2.size() - 1) / 2;
    x.FromMagBytes({buf2.data<uint8_t>() + 1, static_cast<uint64_t>(len)},
                   Endian::little);
    ASSERT_TRUE(x == p7a.x);
    y.FromMagBytes({buf2.data<uint8_t>() + len + 1, static_cast<uint64_t>(len)},
                   Endian::little);
    ASSERT_TRUE(y == p7a.y);

    buf2 = ec->SerializePoint(p5, PointOctetFormat::X962Uncompressed);
    ASSERT_TRUE((buf2.data<uint8_t>()[0]) == 0x4);
    auto p8 = ec->DeserializePoint(buf2, PointOctetFormat::X962Uncompressed);
    ASSERT_TRUE(ec->IsInfinity(p8));
  }

  void TestHashPointWorks(const std::shared_ptr<EcGroup> &ec) {
    std::map<size_t, int> hit_table;
    auto p = ec->MulBase(0_mp);
    int ts = 1 << 10;

    for (int i = 0; i < ts; ++i) {
      auto h = ec->HashPoint(p);
      ++hit_table[h];
      ASSERT_EQ(hit_table[h], 1);
      ec->AddInplace(&p, ec->GetGenerator());
      auto p = ec->MulBase(MPInt(i));
    }
    ASSERT_EQ(hit_table.size(), ts);

    p = ec->MulBase(MPInt(-ts));
    for (int i = 0; i < ts; ++i) {
      auto h = ec->HashPoint(p);
      ++hit_table[h];
      ASSERT_EQ(hit_table[h], 1) << fmt::format("i={}", i);
      ec->AddInplace(&p, ec->GetGenerator());
    }
    ASSERT_EQ(hit_table.size(), ts * 2);

    // same point should have same hash value
    for (int i = 0; i < ts; ++i) {
      auto h = ec->HashPoint(p);
      ++hit_table[h];
      ASSERT_EQ(hit_table[h], 2);
      ec->AddInplace(&p, ec->GetGenerator());
    }
    ASSERT_EQ(hit_table.size(), ts * 2);
  }

  void TestStorePointsInMapWorks(const std::shared_ptr<EcGroup> &ec) {
    auto hash = [&](const EcPoint &p) { return ec->HashPoint(p); };
    auto equal = [&](const EcPoint &p1, const EcPoint &p2) {
      return ec->PointEqual(p1, p2);
    };

    int numel = 500;
    std::unordered_map<EcPoint, int, decltype(hash), decltype(equal)>
        points_map(numel, hash, equal);
    auto p = ec->GetGenerator();
    for (int i = 1; i < numel; ++i) {
      p = ec->Double(p);
      points_map[p] = i;
      if (i % 13 == 0) {
        auto tmp = ec->MulBase(1_mp << i);
        ASSERT_TRUE(ec->PointEqual(p, tmp));
        ASSERT_EQ(hash(p), hash(tmp));
      }
    }
    ASSERT_EQ(points_map.size(), numel - 1);
  }

  void MultiThreadWorks(const std::shared_ptr<EcGroup> &ec) {
    constexpr int64_t ts = 1 << 10;
    std::array<EcPoint, ts> buf;
    auto g = ec->GetGenerator();
    yacl::parallel_for(0, ts, [&](int64_t beg, int64_t end) {
      for (int64_t i = beg; i < end; ++i) {
        auto point = ec->MulBase(MPInt(beg));
        buf[beg] = point;
        for (int64_t i = beg + 1; i < end; ++i) {
          point = ec->Add(point, g);
          buf[i] = point;
        }
      }
    });

    for (int64_t i = 1; i < ts; ++i) {
      ASSERT_TRUE(ec->PointEqual(ec->Add(buf[i - 1], g), buf[i]));
    }
  }

  void TestPairingAlgo() {
    // GIVEN
    auto g1 = pairing_group_->GetGroup1()->GetGenerator();
    auto g2 = pairing_group_->GetGroup2()->GetGenerator();

    // WHEN
    auto field_g = pairing_group_->Pairing(g1, g2);
    auto order = pairing_group_->GetOrder();

    // THEN
    // Test GT group order
    ASSERT_TRUE((bool)gt_->IsIdentityOne(gt_->Pow(field_g, order)));
    // Test Pairing
    for (int i = 0; i < 10; i++) {
      MPInt x;
      MPInt::RandomLtN(order, &x);
      // field_g^x = e(g1, g2)^x
      auto ex = gt_->Pow(field_g, x);
      // g1 * x
      auto g1x = pairing_group_->GetGroup1()->MulBase(x);
      // g2 * x
      auto g2x = pairing_group_->GetGroup2()->MulBase(x);
      // e1 = e(g1^x, g2) = e(g1, g2)^x = ex
      auto e1 = pairing_group_->Pairing(g1x, g2);
      ASSERT_TRUE((bool)gt_->Equal(e1, ex));
      // e1 = e(g1, g2^x) = e(g1, g2)^x = ex
      auto e2 = pairing_group_->Pairing(g1, g2x);
      ASSERT_TRUE((bool)gt_->Equal(e2, ex));
    }

    // Test Pairing = Miller + FinalExp
    for (int i = 0; i < 10; i++) {
      MPInt x;
      MPInt::RandomLtN(order, &x);
      // g1 * x
      auto g1x = pairing_group_->GetGroup1()->MulBase(x);
      // g2 * x
      auto g2x = pairing_group_->GetGroup2()->MulBase(x);

      auto f = pairing_group_->MillerLoop(g1x, g2x);
      auto f1 = pairing_group_->FinalExp(f);
      auto f2 = pairing_group_->Pairing(g1x, g2x);
      ASSERT_TRUE((bool)gt_->Equal(f1, f2));
    }
  }
};

class Bls12381Test : public PairingCurveTest {
 protected:
  void SetUp() override {
    pairing_group_ = PairingGroupFactory::Instance().Create(
        "bls12-381", ArgLib = GetParam());
  }
};

INSTANTIATE_TEST_SUITE_P(Bls12381, Bls12381Test,
                         ::testing::ValuesIn(PairingGroupFactory::Instance()
                                                 .ListLibraries("bls12-381")));

TEST_P(Bls12381Test, SpiTest) {
  if (pairing_group_ != nullptr) {
    EXPECT_STRCASEEQ(pairing_group_->GetPairingName().c_str(), "bls12-381");
    EXPECT_EQ(pairing_group_->GetPairingAlgorithm(), PairingAlgorithm::Ate);
    EXPECT_EQ(pairing_group_->GetSecurityStrength(), 128);
    EXPECT_FALSE(pairing_group_->ToString().empty());

    // Run Other tests
    RunAllTests();
  }
}

class BNSnarkTest : public PairingCurveTest {
 protected:
  void SetUp() override {
    pairing_group_ = PairingGroupFactory::Instance().Create(
        "bn_snark1", ArgLib = GetParam());
  }
};

INSTANTIATE_TEST_SUITE_P(BNSnark, BNSnarkTest,
                         ::testing::ValuesIn(PairingGroupFactory::Instance()
                                                 .ListLibraries("bn_snark1")));

TEST_P(BNSnarkTest, SpiTest) {
  if (pairing_group_ != nullptr) {
    EXPECT_STRCASEEQ(pairing_group_->GetPairingName().c_str(), "bn_snark1");
    EXPECT_EQ(pairing_group_->GetPairingAlgorithm(), PairingAlgorithm::Ate);
    EXPECT_EQ(pairing_group_->GetSecurityStrength(), 100);
    EXPECT_FALSE(pairing_group_->ToString().empty());

    // Run Other tests
    RunAllTests();
  }
}

TEST(Pairing_Multi_Instance_Test, Works) {
  PairingName pairing_name = "bls12-381";
  for (auto lib_name :
       PairingGroupFactory::Instance().ListLibraries(pairing_name)) {
    yacl::parallel_for(0, 10, [&](int64_t, int64_t) {
      std::shared_ptr<PairingGroup> pairing =
          PairingGroupFactory::Instance().Create(pairing_name,
                                                 ArgLib = lib_name);
      pairing->Pairing(pairing->GetGroup1()->GetGenerator(),
                       pairing->GetGroup2()->GetGenerator());
    });
  }
}

}  // namespace yacl::crypto
