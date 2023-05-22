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

#include <memory>
#include <string>

#include "fmt/format.h"
#include "gtest/gtest.h"

#include "yacl/crypto/base/ecc/ec_point.h"
#include "yacl/crypto/base/ecc/ecc_spi.h"
#include "yacl/crypto/base/ecc/libsodium/ed25519_group.h"

namespace yacl::crypto::sodium::test {

class SodiumTest : public ::testing::Test {
 protected:
  std::unique_ptr<EcGroup> ec_ = EcGroupFactory::Create("ed25519", "libsodium");
};

TEST_F(SodiumTest, AffinePointWorks) {
  ASSERT_EQ(ec_->GetLibraryName(), "libsodium");

  AffinePoint ap_g{
      "0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A"_mp,
      "0x6666666666666666666666666666666666666666666666666666666666666658"_mp};
  auto g = ec_->GetAffinePoint(ec_->GetGenerator());
  EXPECT_EQ(ap_g, g);

  auto inf = ec_->GetAffinePoint(ec_->MulBase(0_mp));
  EXPECT_EQ(inf, AffinePoint(0_mp, 1_mp)) << inf;
}

TEST_F(SodiumTest, InfWorks) {
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
}

TEST_F(SodiumTest, NegateWorks) {
  // simple works
  auto g = ec_->MulBase(1_mp);
  EXPECT_TRUE(ec_->PointEqual(g, ec_->GetGenerator()));
  auto g2 = ec_->MulBase(2_mp);
  EXPECT_TRUE(ec_->PointEqual(g2, ec_->Add(g, g)));

  auto ng = ec_->Negate(ec_->GetGenerator());
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

}  // namespace yacl::crypto::sodium::test
