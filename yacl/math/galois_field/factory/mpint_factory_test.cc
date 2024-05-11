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

#include "gtest/gtest.h"

#include "yacl/math/galois_field/factory/gf_spi.h"

namespace yacl::math::test {

class IntrinsicFieldTest : public testing::Test {};

TEST_F(IntrinsicFieldTest, AddWorks) {
  auto gf = GaloisFieldFactory::Instance().Create(
      kPrimeField, ArgLib = kMPIntLib, ArgMod = 13_mp);

  EXPECT_EQ(gf->GetLibraryName(), kMPIntLib);
  EXPECT_EQ(gf->GetFieldName(), kPrimeField);

  EXPECT_EQ(gf->GetOrder(), 13_mp);
  EXPECT_TRUE(gf->GetExtensionDegree() == 1);
  EXPECT_EQ(gf->GetBaseFieldOrder(), 13_mp);

  EXPECT_EQ(gf->GetIdentityZero(), 0_mp);
  EXPECT_EQ(gf->GetIdentityOne(), 1_mp);
}

TEST_F(IntrinsicFieldTest, ScalarWorks) {
  auto gf = GaloisFieldFactory::Instance().Create(
      kPrimeField, ArgLib = kMPIntLib, ArgMod = 13_mp);

  EXPECT_TRUE((bool)gf->IsIdentityZero(0_mp));
  EXPECT_FALSE((bool)gf->IsIdentityZero(1_mp));
  EXPECT_FALSE((bool)gf->IsIdentityOne(0_mp));
  EXPECT_TRUE((bool)gf->IsIdentityOne(1_mp));

  EXPECT_TRUE((bool)gf->IsInField(0_mp));
  EXPECT_TRUE((bool)gf->IsInField(1_mp));
  EXPECT_TRUE((bool)gf->IsInField(12_mp));
  EXPECT_FALSE((bool)gf->IsInField(13_mp));
  EXPECT_FALSE((bool)gf->IsInField(-1_mp));

  EXPECT_TRUE((bool)gf->Equal(0_mp, 0_mp));
  EXPECT_FALSE((bool)gf->Equal(1_mp, 0_mp));
  EXPECT_TRUE((bool)gf->Equal(12_mp, 12_mp));

  // operands //
  EXPECT_EQ(gf->Neg(0_mp), 0_mp);
  EXPECT_EQ(gf->Neg(1_mp), 12_mp);
  EXPECT_EQ(gf->Neg(6_mp), 7_mp);
  EXPECT_EQ(gf->Neg(7_mp), 6_mp);
  EXPECT_EQ(gf->Neg(12_mp), 1_mp);

  EXPECT_EQ(gf->Inv(1_mp), 1_mp);
  EXPECT_EQ(gf->Inv(2_mp), 7_mp);
  EXPECT_EQ(gf->Inv(3_mp), 9_mp);
  EXPECT_EQ(gf->Inv(7_mp), 2_mp);
  EXPECT_EQ(gf->Inv(9_mp), 3_mp);
  EXPECT_ANY_THROW(gf->Inv(0_mp));  // error

  EXPECT_EQ(gf->Add(10_mp, 5_mp), 2_mp);
  EXPECT_NE(gf->Add(10_mp, 5_mp), 3_mp);  // test item not equal

  EXPECT_EQ(gf->Sub(10_mp, 12_mp), 11_mp);  // 23 - 12
  EXPECT_EQ(gf->Sub(0_mp, 0_mp), 0_mp);
  EXPECT_EQ(gf->Sub(10_mp, 1_mp), 9_mp);

  EXPECT_EQ(gf->Mul(10_mp, 12_mp), 3_mp);
  EXPECT_EQ(gf->Mul(1_mp, 12_mp), 12_mp);
  EXPECT_EQ(gf->Mul(0_mp, 12_mp), 0_mp);

  EXPECT_EQ(gf->Div(10_mp, 1_mp), 10_mp);
  EXPECT_EQ(gf->Div(10_mp, 2_mp), 5_mp);
  EXPECT_EQ(gf->Div(12_mp, 1_mp), 12_mp);
  EXPECT_EQ(gf->Div(12_mp, 12_mp), 1_mp);
  EXPECT_EQ(gf->Div(3_mp, 10_mp), 12_mp);
  EXPECT_EQ(gf->Div(3_mp, 12_mp), 10_mp);
  EXPECT_EQ(gf->Div(10_mp, 5_mp), 2_mp);
  EXPECT_ANY_THROW(gf->Div(10_mp, 0_mp));  // error
  EXPECT_EQ(gf->Div(0_mp, 1_mp), 0_mp);
  EXPECT_EQ(gf->Div(0_mp, 11_mp), 0_mp);

  EXPECT_EQ(gf->Pow(10_mp, 0_mp), 1_mp);
  EXPECT_EQ(gf->Pow(10_mp, 1_mp), 10_mp);
  EXPECT_EQ(gf->Pow(10_mp, 2_mp), 9_mp);

  auto r1 = gf->Random();
  auto r2 = gf->Random();
  EXPECT_TRUE((bool)gf->IsInField(r1));
  EXPECT_TRUE(gf->IsInField(r2).IsAll(true));

  // I/O //

  MPInt mp1 = 12_mp;
  Item mp2 = gf->DeepCopy(mp1);
  mp1.DecrOne();
  EXPECT_EQ(mp1, 11_mp);
  EXPECT_EQ(mp2, 12_mp);

  EXPECT_EQ(gf->ToString(mp2), "12");

  // serialize
  Buffer buf = gf->Serialize(mp2);
  auto mp3 = gf->Deserialize(buf);
  EXPECT_EQ(mp3, 12_mp);

  MPInt::RandomExactBits(4096, &mp1);
  buf.reset();
  buf.resize(gf->Serialize(mp1, nullptr, 0));
  auto real_sz = gf->Serialize(mp1, buf.data<uint8_t>(), buf.size());
  EXPECT_EQ(gf->Deserialize(buf), mp1);
  buf.resize(real_sz);
  EXPECT_EQ(gf->Deserialize(buf), mp1);
}

TEST_F(IntrinsicFieldTest, VectorWorks) {
  auto gf = GaloisFieldFactory::Instance().Create(
      kPrimeField, ArgLib = kMPIntLib, ArgMod = 13_mp);

  // test item format
  std::vector<MPInt> a = {1_mp, 2_mp, 3_mp};
  std::vector<MPInt> b = {11_mp, 12_mp, 13_mp};
  auto sum_v = gf->Add(Item::Ref(a), Item::Ref(b));
  ASSERT_TRUE(sum_v.IsArray());
  ASSERT_FALSE(sum_v.IsView());

  // test item (not) equal
  auto sum_sp = sum_v.AsSpan<MPInt>();
  EXPECT_EQ(sum_sp.length(), 3);
  EXPECT_EQ(sum_sp, absl::MakeConstSpan({12_mp, 1_mp, 3_mp}));
  EXPECT_NE(sum_sp, absl::MakeConstSpan({12_mp, 1_mp}));
  EXPECT_NE(sum_sp, absl::MakeConstSpan({12_mp, 1_mp, 3_mp, 12_mp}));
  EXPECT_NE(sum_sp, absl::MakeConstSpan({12_mp, 1_mp, 4_mp}));

  EXPECT_EQ(gf->IsIdentityZero(Item::Take<MPInt>({0_mp, 1_mp, 2_mp, 0_mp})),
            std::vector({true, false, false, true}));
  EXPECT_NE(gf->IsIdentityZero(Item::Take<MPInt>({0_mp, 1_mp, 2_mp, 0_mp})),
            std::vector({true, false, false, false}));
  EXPECT_EQ(gf->IsIdentityOne(Item::Take<MPInt>({0_mp, 1_mp, 2_mp, 0_mp})),
            std::vector({false, true, false, false}));
  EXPECT_EQ(gf->IsInField(
                Item::Take<MPInt>({0_mp, -1_mp, 2_mp, 12_mp, 13_mp, 50_mp})),
            std::vector({true, false, true, true, false, false}));

  // test gf->Equal
  EXPECT_TRUE((bool)gf->Equal(Item::Take<MPInt>({}), Item::Take<MPInt>({})));
  EXPECT_TRUE(
      (bool)gf->Equal(Item::Take<MPInt>({0_mp}), Item::Take<MPInt>({0_mp})));
  EXPECT_TRUE((bool)gf->Equal(Item::Take<MPInt>({0_mp, 10_mp}),
                              Item::Take<MPInt>({0_mp, 10_mp})));
  EXPECT_TRUE((bool)gf->Equal(Item::Take<MPInt>({0_mp, 10_mp, 5_mp, 7_mp}),
                              Item::Take<MPInt>({0_mp, 10_mp, 5_mp, 7_mp})));
  EXPECT_FALSE((bool)gf->Equal(Item::Take<MPInt>({0_mp, 10_mp, 5_mp, 7_mp}),
                               Item::Take<MPInt>({0_mp, 10_mp, 5_mp})));
  EXPECT_FALSE((bool)gf->Equal(Item::Take<MPInt>({0_mp, 10_mp, 5_mp}),
                               Item::Take<MPInt>({0_mp, 10_mp, 5_mp, 7_mp})));
  EXPECT_FALSE((bool)gf->Equal(Item::Take<MPInt>({0_mp, 10_mp, 5_mp, 6_mp}),
                               Item::Take<MPInt>({0_mp, 10_mp, 5_mp, 7_mp})));
  EXPECT_FALSE((bool)gf->Equal(Item::Take<MPInt>({0_mp, 10_mp, 5_mp, 7_mp}),
                               Item::Take<MPInt>({1_mp, 10_mp, 5_mp, 7_mp})));
  EXPECT_FALSE((bool)gf->Equal(Item::Take<MPInt>({0_mp, 1_mp, 2_mp, 3_mp}),
                               Item::Take<MPInt>({3_mp, 2_mp, 1_mp, 0_mp})));

  // operands //

  EXPECT_EQ(gf->Neg(Item::Take<MPInt>({0_mp, 1_mp, 2_mp, 3_mp})),
            std::vector({0_mp, 12_mp, 11_mp, 10_mp}));
  EXPECT_EQ(gf->Inv(Item::Take<MPInt>({1_mp, 2_mp, 3_mp})),
            std::vector({1_mp, 7_mp, 9_mp}));
  EXPECT_ANY_THROW(gf->Inv(Item::Take<MPInt>({0_mp, 2_mp, 3_mp})));  // error

  EXPECT_EQ(gf->Add(Item::Take<MPInt>({0_mp, 1_mp, 2_mp, 3_mp}),
                    Item::Take<MPInt>({7_mp, 6_mp, 5_mp, 4_mp})),
            std::vector({7_mp, 7_mp, 7_mp, 7_mp}));
  EXPECT_EQ(gf->Sub(Item::Take<MPInt>({0_mp, 1_mp, 2_mp, 3_mp}),
                    Item::Take<MPInt>({7_mp, 6_mp, 5_mp, 4_mp})),
            std::vector({6_mp, 8_mp, 10_mp, 12_mp}));
  EXPECT_EQ(gf->Mul(Item::Take<MPInt>({0_mp, 1_mp, 2_mp, 3_mp}),
                    Item::Take<MPInt>({7_mp, 6_mp, 5_mp, 4_mp})),
            std::vector({0_mp, 6_mp, 10_mp, 12_mp}));
  EXPECT_EQ(gf->Div(Item::Take<MPInt>({0_mp, 1_mp, 3_mp, 3_mp}),
                    Item::Take<MPInt>({7_mp, 1_mp, 12_mp, 10_mp})),
            std::vector({0_mp, 1_mp, 10_mp, 12_mp}));
  EXPECT_EQ(gf->Pow(Item::Take<MPInt>({0_mp, 1_mp, 3_mp, 4_mp}), 2_mp),
            std::vector({0_mp, 1_mp, 9_mp, 3_mp}));

  auto r1 = gf->Random(1000);
  auto check1 = gf->IsInField(r1);
  EXPECT_TRUE(check1.IsAll(true));

  auto r2 = gf->Random(1000);
  EXPECT_TRUE(gf->IsInField(r2).IsAll(true));
  EXPECT_FALSE(gf->Equal(r1, r2));
  EXPECT_FALSE(gf->Sub(r1, r2).IsAll(0_mp));
}

TEST_F(IntrinsicFieldTest, VectorIoWorks) {
  MPInt mod;
  MPInt::RandPrimeOver(1024, &mod, PrimeType::Normal);
  auto gf = GaloisFieldFactory::Instance().Create(
      kPrimeField, ArgLib = kMPIntLib, ArgMod = mod);

  // subspan
  auto item1 = Item::Take<MPInt>({0_mp, 1_mp, 2_mp, 3_mp});
  auto item2 = item1.SubItem<MPInt>(0, 1);
  ASSERT_TRUE(item2.IsView());
  ASSERT_FALSE(item2.IsReadOnly());
  ASSERT_TRUE(item2.RawTypeIs<absl::Span<MPInt>>());
  ASSERT_TRUE(gf->Equal(item2, Item::Take<MPInt>({0_mp})));

  // deepcopy
  Item item3 = gf->DeepCopy(item1);
  ASSERT_TRUE(gf->Equal(item1, item3));

  item2.AsSpan<MPInt>()[0] = 10_mp;
  ASSERT_TRUE(gf->Equal(item1, Item::Take<MPInt>({10_mp, 1_mp, 2_mp, 3_mp})));
  ASSERT_TRUE(gf->Equal(item3, Item::Take<MPInt>({0_mp, 1_mp, 2_mp, 3_mp})));

  // to string
  EXPECT_EQ(gf->ToString(item2), "[10]");
  EXPECT_EQ(gf->ToString(item3), "[0, 1, 2, 3]");

  // serialize
  Buffer buf = gf->Serialize(item3);
  auto item4 = gf->Deserialize(buf);
  EXPECT_TRUE(gf->Equal(item3, item4));

  std::vector<MPInt> vt;
  vt.resize(1024);
  for (int i = 0; i < 1024; ++i) {
    MPInt::RandomExactBits(i, &vt[i]);
  }

  item1 = Item::Ref(vt);
  buf.resize(gf->Serialize(item1, nullptr, 0));
  auto real_sz = gf->Serialize(item1, buf.data<uint8_t>(), buf.size());
  EXPECT_EQ(real_sz, buf.size());
  EXPECT_EQ(gf->Deserialize(buf), vt);
}

TEST_F(IntrinsicFieldTest, ScalarInplaceWorks) {
  auto gf = GaloisFieldFactory::Instance().Create(
      kPrimeField, ArgLib = kMPIntLib, ArgMod = 13_mp);

  // operands //
  Item a = 0_mp;
  gf->NegInplace(&a);
  ASSERT_EQ(a, 0_mp);

  gf->AddInplace(&a, 1_mp);  // a = 1
  ASSERT_EQ(a, 1_mp);

  gf->NegInplace(&a);
  ASSERT_EQ(a, 12_mp);

  gf->SubInplace(&a, 5_mp);
  ASSERT_EQ(a, 7_mp);

  gf->InvInplace(&a);
  ASSERT_EQ(a, 2_mp);

  gf->InvInplace(&a);
  ASSERT_EQ(a, 7_mp);

  gf->MulInplace(&a, 4_mp);
  ASSERT_EQ(a, 2_mp);

  gf->DivInplace(&a, 2_mp);
  ASSERT_EQ(a, 1_mp);

  gf->PowInplace(&a, 123456_mp);
  ASSERT_EQ(a, 1_mp);
}

TEST_F(IntrinsicFieldTest, VectorInplaceWorks) {
  auto gf = GaloisFieldFactory::Instance().Create(
      kPrimeField, ArgLib = kMPIntLib, ArgMod = 13_mp);

  std::vector<MPInt> va = {1_mp, 2_mp, 3_mp};
  Item a = Item::Ref(va);

  gf->AddInplace(&a, Item::Take<MPInt>({11_mp, 12_mp, 13_mp}));
  ASSERT_EQ(a.AsSpan<MPInt>(), std::vector({12_mp, 1_mp, 3_mp}));

  gf->NegInplace(&a);
  ASSERT_EQ(a.AsSpan<MPInt>(), std::vector({1_mp, 12_mp, 10_mp}));

  gf->SubInplace(&a, Item::Take<MPInt>({0_mp, 5_mp, 1_mp}));
  ASSERT_EQ(a.AsSpan<MPInt>(), std::vector({1_mp, 7_mp, 9_mp}));

  gf->InvInplace(&a);
  ASSERT_EQ(a.AsSpan<MPInt>(), std::vector({1_mp, 2_mp, 3_mp}));

  gf->MulInplace(&a, Item::Take<MPInt>({7_mp, 7_mp, 7_mp}));
  ASSERT_EQ(a.AsSpan<MPInt>(), std::vector({7_mp, 1_mp, 8_mp}));

  gf->DivInplace(&a, Item::Take<MPInt>({1_mp, 2_mp, 4_mp}));
  ASSERT_EQ(a.AsSpan<MPInt>(), std::vector({7_mp, 7_mp, 2_mp}));

  gf->PowInplace(&a, 2_mp);
  ASSERT_EQ(a.AsSpan<MPInt>(), std::vector({10_mp, 10_mp, 4_mp}));
}

TEST_F(IntrinsicFieldTest, OrderWorks) {
  auto gf = GaloisFieldFactory::Instance().Create(
      kPrimeField, ArgLib = kMPIntLib, ArgMod = 13_mp);
  EXPECT_EQ(gf->GetOrder(), 13_mp);
  auto x = 5_mp;
  EXPECT_EQ(gf->GetOrder(), gf->GetAddGroupOrder());
  EXPECT_EQ(gf->GetOrder() - 1_mp, gf->GetMulGroupOrder());
  // Test additive order, x * order = 0(IdentityZero);
  EXPECT_TRUE((bool)gf->IsIdentityZero(gf->Mul(x, gf->GetAddGroupOrder())));
  // Test multiplicative order, x ^ order = 1(IdentityOne);
  EXPECT_TRUE((bool)gf->IsIdentityOne(gf->Pow(x, gf->GetMulGroupOrder())));
}

}  // namespace yacl::math::test
