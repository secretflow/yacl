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

#include "yacl/crypto/ecc/mcl/mcl_ec_group.h"

namespace yacl::crypto {
// for test
extern std::map<CurveName, int> Name2MclCurveEnum;
}  // namespace yacl::crypto

namespace yacl::crypto::test {

TEST(MclTest, MclWorks) {
  // Curve Instances ok
  for (auto it : Name2MclCurveEnum) {
    MclEGFactory::Create(GetCurveMetaByName(it.first));
  }
  {
    auto tmp = MclEGFactory::Create(GetCurveMetaByName("secp256k1"));
    auto* group = dynamic_cast<MclSecp256k1*>(tmp.get());

    auto g = group->GetGenerator();

    auto gadd = group->Add(g, g);
    auto gdbl = group->Double(g);
    ASSERT_TRUE(group->PointEqual(gadd, gdbl));
    auto gcopy = group->CopyPoint(g);
    ASSERT_TRUE(group->PointEqual(gcopy, g));
    ASSERT_FALSE(group->PointEqual(gcopy, gdbl));
    group->DoubleInplace(&gcopy);
    ASSERT_TRUE(group->PointEqual(gcopy, gdbl));

    auto p = group->MulBase(333_mp);
    auto affine = group->GetAffinePoint(p);
    auto p2 = group->GetMclPoint(affine);
    EXPECT_TRUE(group->PointEqual(p, p2));
  }

  {
    auto tmp = MclEGFactory::Create(GetCurveMetaByName("p-192"));
    auto* group = dynamic_cast<MclNistP192*>(tmp.get());
    auto g = group->GetGenerator();
    auto gadd = group->Add(g, g);
    auto gdbl = group->Double(g);
    ASSERT_TRUE(group->PointEqual(gadd, gdbl));
    auto gcopy = group->CopyPoint(g);
    ASSERT_TRUE(group->PointEqual(gcopy, g));
    ASSERT_FALSE(group->PointEqual(gcopy, gdbl));
    group->DoubleInplace(&gcopy);
    ASSERT_TRUE(group->PointEqual(gcopy, gdbl));

    auto p = group->MulBase(333_mp);
    auto affine = group->GetAffinePoint(p);
    auto p2 = group->GetMclPoint(affine);
    EXPECT_TRUE(group->PointEqual(p, p2));
  }

  // multi curve instance test
  {
    auto tmp1 = MclEGFactory::Create(GetCurveMetaByName("p-192"));
    auto* group1 = dynamic_cast<MclNistP192*>(tmp1.get());
    auto tmp2 = MclEGFactory::Create(GetCurveMetaByName("secp192k1"));
    auto* group2 = dynamic_cast<MclSecp192k1*>(tmp2.get());
    ASSERT_TRUE(group1->GetOrder() != group2->GetOrder());
    ASSERT_TRUE(group1->GetField() != group2->GetField());
    // Order
    ASSERT_TRUE(MclNistP192::Fr::getOp().mp != MclSecp192k1::Fr::getOp().mp);
    // Field
    ASSERT_TRUE(MclNistP192::BaseFp::getOp().mp !=
                MclSecp192k1::BaseFp::getOp().mp);
  }
}

TEST(MclTest, HashToCurveWorks) {
  auto curve = MclEGFactory::Create(GetCurveMetaByName("secp256k1"));
  auto is_unique = [&](EcPoint p) {
    ASSERT_TRUE(curve->IsInCurveGroup(p));

    static std::vector<EcPoint> v;
    for (const auto& item : v) {
      ASSERT_FALSE(curve->PointEqual(item, p));
    }
    v.emplace_back(std::move(p));
  };

  for (int i = 0; i < 1000; ++i) {
    is_unique(curve->HashToCurve(HashToCurveStrategy::TryAndIncrement_SHA2,
                                 fmt::format("id{}", i)));
    is_unique(curve->HashToCurve(HashToCurveStrategy::TryAndIncrement_SM,
                                 fmt::format("id{}", i)));
    is_unique(curve->HashToCurve(fmt::format("id{}", i)));
    // Same as above
    // is_unique(curve->HashToCurve(HashToCurveStrategy::TryAndIncrement_BLAKE3,
    //                              fmt::format("id{}", i)));
  }
}

}  // namespace yacl::crypto::test
