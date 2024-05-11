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

#include "yacl/crypto/pairing/factory/mcl_pairing_group.h"
#include "yacl/crypto/rand/rand.h"

namespace yacl::crypto {
extern std::map<CurveName, int> Name2MclPairingEnum;
}  // namespace yacl::crypto

namespace yacl::crypto::test {

class MclPairingTest : public ::testing::Test {
 protected:
  PairingMeta meta_;
  std::unique_ptr<PairingGroup> pairing_group_;
  std::shared_ptr<EcGroup> group1_;
  std::shared_ptr<EcGroup> group2_;
  std::shared_ptr<GroupTarget> gt_;

  void TestPairingAlgo() {
    // GIVEN
    auto g1 = group1_->GetGenerator();
    auto g2 = group2_->GetGenerator();

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
      auto g1x = group1_->MulBase(x);
      // g2 * x
      auto g2x = group2_->MulBase(x);
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
      auto g1x = group1_->MulBase(x);
      // g2 * x
      auto g2x = group2_->MulBase(x);

      auto f = pairing_group_->MillerLoop(g1x, g2x);
      auto f1 = pairing_group_->FinalExp(f);
      auto f2 = pairing_group_->Pairing(g1x, g2x);
      ASSERT_TRUE((bool)gt_->Equal(f1, f2));
    }
  }

  void TestHashToCurve(std::shared_ptr<EcGroup> ec) {
    std::vector<EcPoint> v;
    for (int i = 0; i < 1000; ++i) {
      auto p = ec->HashToCurve(HashToCurveStrategy::TryAndIncrement_SHA2,
                               fmt::format("id{}", i));
      //  Same as above
      auto p2 = ec->HashToCurve(fmt::format("id{}", i));
      ASSERT_TRUE(ec->IsInCurveGroup(p));
      ASSERT_TRUE(ec->PointEqual(p, p2));
      for (const auto& item : v) {
        ASSERT_FALSE(ec->PointEqual(item, p));
      }
      v.emplace_back(std::move(p));
    }
  }
};

#define MCL_PAIRING_TEST(class_name, pairing_name)                           \
  class MclPairing##class_name##Test : public MclPairingTest {               \
   protected:                                                                \
    void SetUp() override {                                                  \
      pairing_group_ = MclPGFactory::CreateByName(pairing_name);             \
      group1_ = pairing_group_->GetGroup1();                                 \
      group2_ = pairing_group_->GetGroup2();                                 \
      gt_ = pairing_group_->GetGroupT();                                     \
    }                                                                        \
  };                                                                         \
  TEST_F(MclPairing##class_name##Test, Works) {                              \
    fmt::print("Begin test pairing {}\n", pairing_group_->GetPairingName()); \
    TestPairingAlgo();                                                       \
    TestHashToCurve(pairing_group_->GetGroup1());                            \
    TestHashToCurve(pairing_group_->GetGroup2());                            \
    fmt::print("End test pairing {}\n", pairing_group_->GetPairingName());   \
  }

MCL_PAIRING_TEST(Bls12381, "bls12-381");
MCL_PAIRING_TEST(BNSnark, "bn_snark1");

#ifdef MCL_ALL_PAIRING_FOR_YACL
// MCL_PAIRING_TEST(BN254, "bn254");
// MCL_PAIRING_TEST(BN384M, "bn382m");
// MCL_PAIRING_TEST(BN384R, "bn382r");
// MCL_PAIRING_TEST(BN462, "bn462");
// MCL_PAIRING_TEST(BN160, "bn160");
// MCL_PAIRING_TEST(Bls12461, "bls12-461");
// MCL_PAIRING_TEST(BN256, "bn256");
#endif

TEST(MultInstance, OK) {
  for (uint32_t i = 0; i < 5; i++) {
    for (auto it = Name2MclPairingEnum.begin(); it != Name2MclPairingEnum.end();
         it++) {
      MclPGFactory::CreateByName(it->first);
    }
  }
}

}  // namespace yacl::crypto::test
