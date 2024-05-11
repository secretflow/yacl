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

#include "gtest/gtest.h"

#include "yacl/crypto/ecc/FourQlib/FourQ_group.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/utils/spi/spi_factory.h"

namespace yacl::crypto::FourQ {

extern MPInt F2elm2MPInt(const f2elm_t f2elm);
extern void MPIntToF2elm(const MPInt& x, f2elm_t f2elm);

}  // namespace yacl::crypto::FourQ

namespace yacl::crypto::FourQ::test {

std::ostream& operator<<(std::ostream& os, const EcPoint& p) {
  const auto* r1 =
      reinterpret_cast<const point_extproj*>(std::get<Array160>(p).data());

  return os << fmt::format("[X={}, Y={}, Z={}, Ta={}, Tb={}]",
                           F2elm2MPInt(r1->x), F2elm2MPInt(r1->y),
                           F2elm2MPInt(r1->z), F2elm2MPInt(r1->ta),
                           F2elm2MPInt(r1->tb));
}

class FourQTest : public ::testing::Test {
 protected:
  std::unique_ptr<EcGroup> ec_ =
      EcGroupFactory::Instance().Create("FourQ", ArgLib = "FourQlib");
};

TEST_F(FourQTest, CopyPointWorks) {
  // Convert function
  f2elm_t f;
  MPIntToF2elm(123456789_mp, f);
  EXPECT_EQ(F2elm2MPInt(f), 123456789_mp);

  // CopyPoint: point_extproj -> point_extproj
  auto ecp1 = ec_->MulBase(852_mp);
  auto ecp2 = ec_->CopyPoint(ecp1);
  EXPECT_TRUE(ec_->PointEqual(ecp1, ecp2));

  // check is deep copy
  ec_->AddInplace(&ecp1, ec_->GetGenerator());
  EXPECT_FALSE(ec_->PointEqual(ecp1, ecp2));

  auto ecp3 = ec_->MulBase(853_mp);
  EXPECT_TRUE(ec_->PointEqual(ecp1, ecp3));

  // CopyPoint: affine_point -> point_extproj
  auto ap = ec_->GetAffinePoint(ecp1);
  EXPECT_TRUE(ec_->PointEqual(ecp1, ec_->CopyPoint(ap)));
}

TEST_F(FourQTest, AffinePointWorks) {
  ASSERT_EQ(ec_->GetLibraryName(), "FourQlib");

  AffinePoint ap_g{
      "0x1E1F553F2878AA9C96869FB360AC77F61A3472237C2FB305286592AD7B3833AA"_mp,
      "0x6E1C4AF8630E024249A7C344844C8B5C0E3FEE9BA120785AB924A2462BCBB287"_mp};
  auto g = ec_->GetAffinePoint(ec_->GetGenerator());
  EXPECT_EQ(ap_g, g);

  EcPoint new_g = ec_->CopyPoint(ap_g);
  EXPECT_TRUE(ec_->PointEqual(new_g, ec_->GetGenerator()));

  auto inf = ec_->GetAffinePoint(ec_->MulBase(0_mp));
  EXPECT_EQ(inf, AffinePoint(0_mp, 1_mp)) << inf;
  EXPECT_TRUE(ec_->PointEqual(ec_->CopyPoint(inf), ec_->MulBase(0_mp)));

  auto any_p = ec_->MulBase(123456_mp);
  auto any_ap = ec_->GetAffinePoint(any_p);
  EXPECT_TRUE(ec_->PointEqual(ec_->CopyPoint(any_ap), any_p));
}

TEST_F(FourQTest, InfWorks) {
  auto g = ec_->GetGenerator();
  EXPECT_TRUE(ec_->IsInCurveGroup(g));

  auto inf = ec_->MulBase(0_mp);
  auto inf2 = ec_->CopyPoint(inf);
  EXPECT_TRUE(ec_->PointEqual(inf, inf2));
  EXPECT_FALSE(ec_->PointEqual(inf, g));
  EXPECT_TRUE(ec_->IsInfinity(inf2));
  EXPECT_TRUE(ec_->IsInCurveGroup(inf2));

  ec_->AddInplace(&inf, ec_->GetGenerator());
  EXPECT_FALSE(ec_->PointEqual(inf, inf2));
  EXPECT_TRUE(ec_->PointEqual(inf, g));

  inf = ec_->MulBase(0_mp);
  inf2 = ec_->CopyPoint(AffinePoint(0_mp, 1_mp));
  EXPECT_EQ(ec_->HashPoint(inf), ec_->HashPoint(inf2));
  EXPECT_TRUE(ec_->PointEqual(inf, inf2));
}

TEST_F(FourQTest, NegateWorks) {
  // simple works
  auto g = ec_->MulBase(1_mp);
  EXPECT_TRUE(ec_->PointEqual(g, ec_->GetGenerator()));
  auto g2 = ec_->MulBase(2_mp);
  EXPECT_TRUE(ec_->PointEqual(g2, ec_->Add(g, g)));

  EcPoint ng = ec_->Negate(ec_->GetGenerator());
  EXPECT_TRUE(ec_->PointEqual(ng, ec_->MulBase(-1_mp)));
  EXPECT_TRUE(ec_->PointEqual(ng, ec_->Sub(g, g2)));
  auto inf = ec_->Add(ng, ec_->GetGenerator());
  EXPECT_TRUE(ec_->IsInfinity(inf));
  ec_->NegateInplace(&inf);
  EXPECT_TRUE(ec_->IsInfinity(inf));
  EXPECT_EQ(ec_->GetAffinePoint(inf), AffinePoint(0_mp, 1_mp));

  EXPECT_TRUE(ec_->PointEqual(ec_->MulBase(-2_mp), ec_->Add(ng, ng)));
  EXPECT_TRUE(ec_->PointEqual(ec_->MulBase(-1000_mp),
                              ec_->Negate(ec_->MulBase(1000_mp))));
}

}  // namespace yacl::crypto::FourQ::test
