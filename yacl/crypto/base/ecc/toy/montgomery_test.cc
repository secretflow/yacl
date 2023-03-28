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

#include "yacl/crypto/base/ecc/toy/montgomery.h"

#include "gtest/gtest.h"

namespace yacl::crypto::toy {
std::unique_ptr<EcGroup> Create(const CurveMeta &meta);
}

namespace yacl::crypto::toy::test {

TEST(ToyMTest, MetaTest) {
  auto curve = Create(GetCurveMetaByName("curve25519"));
  EXPECT_STRCASEEQ(curve->GetCurveName().c_str(), "curve25519");
  EXPECT_EQ(
      curve->GetField(),
      "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"_mp);
  EXPECT_EQ(
      curve->GetOrder(),
      "0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"_mp);

  EXPECT_EQ(curve->GetAffinePoint(curve->GetGenerator()).x, 9_mp);
}

MPInt LeHex2Mp(std::string_view src) {
  YACL_ENFORCE(src.size() % 2 == 0);
  std::string result;
  result.reserve(src.size());

  for (std::size_t i = src.size(); i != 0; i -= 2) {
    result.append(src, i - 2, 2);
  }

  return MPInt(result, 16);
}

// The test cases below are come from RFC 7748
TEST(ToyMTest, X25519Works) {
  auto curve = Create(GetCurveMetaByName("curve25519"));

  // case 1
  auto s = LeHex2Mp(
      "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
  AffinePoint p;
  p.x = LeHex2Mp(
      "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
  AffinePoint exp;
  exp.x = LeHex2Mp(
      "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
  auto res = curve->Mul(p, s);
  EXPECT_EQ(curve->GetAffinePoint(res).x, exp.x);
  EXPECT_TRUE(curve->PointEqual(res, exp));

  // case 2
  s = LeHex2Mp(
      "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
  p.x = LeHex2Mp(
      "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a413");
  exp.x = LeHex2Mp(
      "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
  res = curve->Mul(p, s);
  EXPECT_EQ(curve->GetAffinePoint(res).x, exp.x);
  EXPECT_TRUE(curve->PointEqual(res, exp));

  s = LeHex2Mp(
      "0900000000000000000000000000000000000000000000000000000000000000");
  p.x = LeHex2Mp(
      "0900000000000000000000000000000000000000000000000000000000000000");
  for (int i = 1; i <= 1000; ++i) {
    res = curve->Mul(p, s);
    p.x = s;
    s = curve->GetAffinePoint(res).x;
    if (i == 1) {
      EXPECT_EQ(curve->GetAffinePoint(res).x,
                LeHex2Mp("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e"
                         "80311ae3079"));
    }
    if (i == 1000) {
      EXPECT_EQ(curve->GetAffinePoint(res).x,
                LeHex2Mp("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb"
                         "94d99532c51"));
    }
  }
}

}  // namespace yacl::crypto::toy::test
