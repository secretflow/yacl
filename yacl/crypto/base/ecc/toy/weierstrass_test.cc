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

#include "yacl/crypto/base/ecc/toy/weierstrass.h"

#include "gtest/gtest.h"

namespace yacl::crypto::toy::test {

TEST(CurveTest, Secp256k1Works) {
  auto curve = ToyWeierstrassGroup::Create(GetCurveMetaByName("secp256k1"));
  EXPECT_EQ(curve->GetCurveName(), "secp256k1");
  EXPECT_EQ(curve->GetCurveForm(), CurveForm::Weierstrass);
  EXPECT_EQ(curve->GetLibraryName(), "Toy");
  EXPECT_EQ(curve->GetCofactor(), 1_mp);
  EXPECT_EQ(curve->GetSecurityStrength(), 128);

  auto g = curve->GetAffinePoint(curve->GetGenerator());
  EXPECT_EQ(
      g.x,
      "55066263022277343669578718895168534326250603453777594175500187360389116729240"_mp);
  EXPECT_EQ(
      g.y,
      "32670510020758816978083085130507043184471273380659243275938904335757337482424"_mp);
  EXPECT_TRUE(curve->IsInCurveGroup(g));
  EXPECT_TRUE(curve->IsInfinity(curve->Add(curve->Negate(g), g)));

  // small case: add & mul
  auto g2a = curve->Add(curve->GetGenerator(), curve->GetGenerator());
  auto g2b = curve->Mul(2_mp, curve->GetGenerator());
  auto g2c = curve->MulBase(2_mp);
  EXPECT_TRUE(curve->PointEqual(g2a, g2b));
  EXPECT_TRUE(curve->PointEqual(g2a, g2c));
  EXPECT_EQ(
      curve->GetAffinePoint(g2a).x,
      "89565891926547004231252920425935692360644145829622209833684329913297188986597"_mp);
  EXPECT_EQ(
      curve->GetAffinePoint(g2a).y,
      "12158399299693830322967808612713398636155367887041628176798871954788371653930"_mp);
  EXPECT_TRUE(curve->IsInCurveGroup(g2a));
  EXPECT_FALSE(curve->IsInfinity(g2a));

  EXPECT_TRUE(curve->IsInfinity(curve->Mul(0_mp, g2c)));
  EXPECT_TRUE(curve->PointEqual(curve->MulBase(-1_mp),
                                curve->Negate(curve->GetGenerator())));

  // small case: sub & div
  auto g_sub = curve->Sub(g2a, curve->GetGenerator());
  EXPECT_TRUE(curve->IsInCurveGroup(g_sub));
  EXPECT_TRUE(curve->PointEqual(g_sub, curve->GetGenerator()));
  g_sub = curve->Sub(g_sub, curve->GetGenerator());
  EXPECT_TRUE(curve->IsInfinity(g_sub));
  EXPECT_TRUE(curve->IsInCurveGroup(g_sub));

  auto g_div = curve->Div(g2b, 2_mp);
  EXPECT_TRUE(curve->PointEqual(g_div, curve->GetGenerator()));

  // big case
  auto scalar1 =
      "0xcb65830cae137b30b5c29f16d5737b467f23437a8224b2493837682b10161a03"_mp;
  auto sg = curve->GetAffinePoint(curve->MulBase(scalar1));
  EXPECT_EQ(
      sg.x,
      "74190344000711057045730468313879464759665521818199660244243582541532332986299"_mp);
  EXPECT_EQ(
      sg.y,
      "40347636707027399493019052782324680321641501993182836783803325611213065140316"_mp);
  EXPECT_TRUE(
      curve->PointEqual(curve->Div(sg, scalar1), curve->GetGenerator()));

  auto scalar2 =
      "-0x6a5ab59522b1f30782d104e7357a62a4765bc57ebd5279b9ea573a6eaed8593b"_mp;
  auto sg2 = curve->GetAffinePoint(curve->Mul(scalar2, sg));
  EXPECT_EQ(
      sg2.x,
      "97558491001741493100682586125779371803575554251176920086377653822240438145201"_mp);
  EXPECT_EQ(
      sg2.y,
      "3873643218096366517011519658811590004229407662248396464966752139819222285242"_mp);
  EXPECT_TRUE(curve->PointEqual(curve->Div(sg2, scalar2), sg));

  EXPECT_TRUE(curve->PointEqual(curve->Mul(scalar2, curve->MulBase(scalar1)),
                                curve->Mul(scalar1, curve->MulBase(scalar2))));

  auto sg3 =
      curve->GetAffinePoint(curve->MulDoubleBase(12345_mp, sg2, -6789_mp));
  EXPECT_EQ(
      sg3.x,
      "79914623817369507497155870284859519547754128956319824651094395882608386841415"_mp);
  EXPECT_EQ(
      sg3.y,
      "42371308820993604738923640079906132358355437118721947350660194247433151072035"_mp);
}

TEST(CurveTest, SerializeWorks) {
  auto curve = ToyWeierstrassGroup::Create(GetCurveMetaByName("sm2"));
  auto p1 = curve->MulBase(123456789_mp);
  auto buf = curve->SerializePoint(p1);
  auto p2 = curve->DeserializePoint(buf);

  EXPECT_TRUE(curve->IsInCurveGroup(p2));
  EXPECT_FALSE(ToyWeierstrassGroup::Create(GetCurveMetaByName("secp256k1"))
                   ->IsInCurveGroup(p2));
  EXPECT_TRUE(
      curve->PointEqual(curve->Div(p2, 123456789_mp), curve->GetGenerator()));
}

}  // namespace yacl::crypto::toy::test
