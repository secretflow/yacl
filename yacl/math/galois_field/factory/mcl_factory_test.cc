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

#include "yacl/math/galois_field/factory/mcl_factory.h"

#include "gtest/gtest.h"

#include "yacl/crypto/ecc/mcl/mcl_util.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/math/galois_field/factory/gf_spi.h"

namespace yacl::math::test {

template <typename F>
class MclFieldTest : public ::testing::Test {
 protected:
  using T = typename F::T_;

  std::shared_ptr<GaloisField> field_;  // This lib/curve we should to test
  std::string filed_name_;
  bool is_sub_field_ = false;

  void RunAllTests() {
    // fmt::print("Begin to test mcl field {} \n", filed_name_);
    TestCompare();
    TestArithmetic();
    TestArithmeticVector();
    // TestOrder();
    TestSerialize();
    // fmt::print("End to test mcl field {} \n", filed_name_);
  }

  void TestCompare() {
    auto f1 = field_->GetIdentityZero();
    EXPECT_TRUE((bool)field_->IsIdentityZero(f1));
    f1 = field_->GetIdentityOne();
    EXPECT_TRUE((bool)field_->IsIdentityOne(f1));
    EXPECT_TRUE((bool)field_->Equal(f1, field_->GetIdentityOne()));

    auto f2 = field_->Random();
    EXPECT_TRUE((bool)field_->Equal(f2, f2));
    EXPECT_FALSE((bool)field_->Equal(f1, f2));
  }

  void TestArithmetic() {
    // GIVEN
    auto f1 = field_->Random();
    auto f2 = field_->Random();

    // THEN
    // Add, AddInplace
    auto add_ret = field_->Add(f1, f2);
    EXPECT_TRUE((bool)field_->Equal(add_ret, field_->Add(f2, f1)));
    Item temp = field_->DeepCopy(f1);
    field_->AddInplace(&temp, f2);
    EXPECT_TRUE((bool)field_->Equal(add_ret, temp));

    // Neg & Sub, SubInplace
    EXPECT_TRUE((bool)field_->IsIdentityZero(field_->Add(f1, field_->Neg(f1))));
    auto sub_ret = field_->Sub(f1, f2);
    EXPECT_TRUE((bool)field_->Equal(sub_ret, field_->Add(f1, field_->Neg(f2))));
    temp = field_->DeepCopy(f1);
    field_->SubInplace(&temp, f2);
    EXPECT_TRUE((bool)field_->Equal(sub_ret, temp));

    // Mul, MulInplace
    auto mul_ret = field_->Mul(f1, f2);
    EXPECT_TRUE((bool)field_->Equal(mul_ret, field_->Mul(f2, f1)));
    temp = field_->DeepCopy(f1);
    field_->MulInplace(&temp, f2);
    EXPECT_TRUE((bool)field_->Equal(mul_ret, temp));

    // Pow, PowInplace
    // Test f1^r
    auto r = 1000_mp;
    auto pow_temp = field_->GetIdentityOne();
    for (int i = 0; i < 1000; i++) {
      field_->MulInplace(&pow_temp, f1);
    }
    auto pow_ret1 = field_->Pow(f1, r);
    EXPECT_TRUE((bool)field_->Equal(pow_ret1, pow_temp));
    auto pow_ret2 = field_->DeepCopy(f1);
    field_->PowInplace(&pow_ret2, r);
    EXPECT_TRUE((bool)field_->Equal(pow_ret2, pow_temp));

    // Div, DivInplace & Inv
    EXPECT_TRUE((bool)field_->IsIdentityOne(field_->Div(f1, f1)));
    auto div_ret = field_->Div(f1, f2);
    temp = field_->DeepCopy(f1);
    field_->DivInplace(&temp, f2);
    EXPECT_TRUE((bool)field_->Equal(temp, div_ret));
    EXPECT_TRUE((bool)field_->IsIdentityOne(
        field_->Mul(field_->Div(f1, f2), field_->Div(f2, f1))));
    EXPECT_TRUE((bool)field_->IsIdentityOne(field_->Mul(f1, field_->Inv(f1))));
  }

  void TestArithmeticVector() {
    // GIVEN
    auto t1 = std::vector({field_->Random().As<T>(), field_->Random().As<T>(),
                           field_->Random().As<T>(), field_->Random().As<T>()});
    auto t2 = std::vector({field_->Random().As<T>(), field_->Random().As<T>(),
                           field_->Random().As<T>(), field_->Random().As<T>()});
    auto f1 = Item::Ref(t1);  // 4 items
    auto f2 = Item::Ref(t2);  // 4 items

    // THEN
    // Add, AddInplace
    auto add_ret = field_->Add(f1, f2);
    EXPECT_TRUE((bool)field_->Equal(add_ret, field_->Add(f2, f1)));
    Item temp = field_->DeepCopy(f1);
    field_->AddInplace(&temp, f2);
    EXPECT_TRUE((bool)field_->Equal(add_ret, temp));

    // Neg & Sub, SubInplace
    EXPECT_EQ(field_->IsIdentityZero(field_->Add(f1, field_->Neg(f1))),
              std::vector<bool>(4, true));
    auto sub_ret = field_->Sub(f1, f2);
    EXPECT_TRUE((bool)field_->Equal(sub_ret, field_->Add(f1, field_->Neg(f2))));
    temp = field_->DeepCopy(f1);
    field_->SubInplace(&temp, f2);
    EXPECT_TRUE((bool)field_->Equal(sub_ret, temp));

    // Mul, MulInplace
    auto mul_ret = field_->Mul(f1, f2);
    EXPECT_TRUE((bool)field_->Equal(mul_ret, field_->Mul(f2, f1)));
    temp = field_->DeepCopy(f1);
    field_->MulInplace(&temp, f2);
    EXPECT_TRUE((bool)field_->Equal(mul_ret, temp));

    // Pow, PowInplace
    // Test f1^r
    auto r = 1000_mp;
    auto ones = std::vector(
        {field_->GetIdentityOne().As<T>(), field_->GetIdentityOne().As<T>(),
         field_->GetIdentityOne().As<T>(), field_->GetIdentityOne().As<T>()});
    auto pow_temp = Item::Ref(ones);
    for (int i = 0; i < 1000; i++) {
      field_->MulInplace(&pow_temp, f1);
    }
    auto pow_ret1 = field_->Pow(f1, r);
    EXPECT_TRUE((bool)field_->Equal(pow_ret1, pow_temp));
    auto pow_ret2 = field_->DeepCopy(f1);
    field_->PowInplace(&pow_ret2, r);
    EXPECT_TRUE((bool)field_->Equal(pow_ret2, pow_temp));

    // Div, DivInplace & Inv
    EXPECT_EQ(field_->IsIdentityOne(field_->Div(f1, f1)),
              std::vector<bool>(4, true));
    auto div_ret = field_->Div(f1, f2);
    temp = field_->DeepCopy(f1);
    field_->DivInplace(&temp, f2);
    EXPECT_TRUE((bool)field_->Equal(temp, div_ret));
    EXPECT_EQ(field_->IsIdentityOne(
                  field_->Mul(field_->Div(f1, f2), field_->Div(f2, f1))),
              std::vector<bool>(4, true));
    EXPECT_EQ(field_->IsIdentityOne(field_->Mul(f1, field_->Inv(f1))),
              std::vector<bool>(4, true));
  }

  void TestOrder() {
    auto order = field_->GetOrder();

    if (field_->GetExtensionDegree() == 1) {
      auto f = field_->Random();
      EXPECT_EQ(field_->GetOrder() - 1_mp, field_->GetMulGroupOrder());
      EXPECT_EQ(field_->GetOrder(), field_->GetAddGroupOrder());
      // mul order
      if (!field_->GetMulGroupOrder().IsZero()) {
        auto t = field_->Pow(f, field_->GetMulGroupOrder());
        EXPECT_TRUE((bool)field_->Equal(t, field_->GetIdentityOne()));
      }
      // add order
      if (!field_->GetAddGroupOrder().IsZero()) {
        typename T::BaseFp order_fp;
        // TODO: mpint 2 Fp
        // order_fp.setMpz(math::Mp2Mpz(order));
        auto t = field_->Mul(f, order_fp);
        EXPECT_TRUE((bool)field_->Equal(t, field_->GetIdentityZero()));
      }
    }
  }

  void TestSerialize() {
    for (int i = 0; i < 1; i++) {
      auto f = field_->Random();
      // Serialize
      auto buf = field_->Serialize(f);
      auto f1 = field_->Deserialize(buf);
      EXPECT_TRUE((bool)field_->Equal(f, f1));
      // toString
      auto one = field_->GetIdentityOne();
      if (field_->GetExtensionDegree() == 1) {
        EXPECT_EQ(field_->ToString(one), "1");
      } else if (field_->GetExtensionDegree() == 2) {
        EXPECT_EQ(field_->ToString(one), "1 0");
      } else if (field_->GetExtensionDegree() == 6) {
        EXPECT_EQ(field_->ToString(one), "1 0 0 0 0 0");
      } else if (field_->GetExtensionDegree() == 12) {
        EXPECT_EQ(field_->ToString(one), "1 0 0 0 0 0 0 0 0 0 0 0");
      }
    }
  }
};

#define DEFAULT_FIELD_TEST(intern_type, fieldType, degree, maxBitSize)      \
  class Mcl##intern_type##Test                                              \
      : public MclFieldTest<MclField<intern_type, degree>> {                \
    void SetUp() override {                                                 \
      field_ = GaloisFieldFactory::Instance().Create(                       \
          fieldType, ArgLib = kMclLib,                                      \
          ArgMod = "0xffffffffffffffffffffffffffffffffffffffffffffff13"_mp, \
          ArgDegree = degree, ArgMaxBitSize = maxBitSize);                  \
      filed_name_ = field_->GetFieldName();                                 \
    }                                                                       \
  };                                                                        \
  TEST_F(Mcl##intern_type##Test, Works) { RunAllTests(); }

DEFAULT_FIELD_TEST(DefaultFp, kPrimeField, 1, 512);
DEFAULT_FIELD_TEST(FpWithSize256, kPrimeField, 1, 256);
DEFAULT_FIELD_TEST(DefaultFp2, kExtensionField, 2, 512);
DEFAULT_FIELD_TEST(DefaultFp6, kExtensionField, 6, 512);
DEFAULT_FIELD_TEST(DefaultFp12, kExtensionField, 12, 512);

/**
 * #define DECLARE_PAIRING_FIELD_TEST_CLASS(classname, pairing_name)      \
 *  class MclPairing##classname##GTTest                                  \
 *    : public MclFieldTest<math::MclPairing##classname##GT> {       \
 *   void SetUp() override {                                            \
 *     auto pairing = math::MclPGFactory::CreateByName(pairing_name); \
 *    field_ = pairing->GetGroupT();                                   \
 *      filed_name_ = "MclPairing" #classname "GTField";                 \
 *     is_sub_field_ = true;                                            \
 *    }                                                                  \
 * };                                                                   \
 *  TEST_F(MclPairing##classname##GTTest, Works) { RunAllTests(); }
 */

// DECLARE_PAIRING_FIELD_TEST_CLASS(Bls12381, "bls12-381");
// DECLARE_PAIRING_FIELD_TEST_CLASS(BNSnark, "bn_snark1");

// #ifdef MCL_ALL_PAIRING_FOR_YACL
// DECLARE_PAIRING_FIELD_TEST_CLASS(BN254, "bn254");
// DECLARE_PAIRING_FIELD_TEST_CLASS(BN384M, "bn382m");
// DECLARE_PAIRING_FIELD_TEST_CLASS(BN384R, "bn382r");
// DECLARE_PAIRING_FIELD_TEST_CLASS(BN462, "bn462");
// DECLARE_PAIRING_FIELD_TEST_CLASS(BN160, "bn160");
// DECLARE_PAIRING_FIELD_TEST_CLASS(Bls12461, "bls12-461");
// DECLARE_PAIRING_FIELD_TEST_CLASS(BN256, "bn256");
// #endif

}  // namespace yacl::math::test
