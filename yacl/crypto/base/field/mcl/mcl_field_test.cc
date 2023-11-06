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

#include "yacl/crypto/base/field/mcl/mcl_field.h"

#include "gtest/gtest.h"

#include "yacl/crypto/base/ecc/mcl/mcl_pairing_group.h"
#include "yacl/crypto/utils/rand.h"

namespace yacl::crypto::hmcl::test {

class MclFieldTest : public ::testing::Test {
 protected:
  std::shared_ptr<Field> field_;  // This lib/curve we should to test
  std::string filed_name_;
  bool is_sub_field_ = false;

  void RunAllTests() {
    fmt::print("Begin to test mcl field {} \n", filed_name_);
    TestCompare();
    TestArithmetic();
    if (field_->GetExtensionDegree() == 1) {
      TestOrder();
    }
    TestSerialize();
    fmt::print("End to test mcl field {} \n", filed_name_);
  }

  void TestCompare() {
    auto f1 = field_->MakeInstance();
    EXPECT_TRUE(field_->IsZero(f1));
    field_->SetOne(&f1);
    EXPECT_TRUE(field_->IsOne(f1));
    EXPECT_TRUE(field_->Equal(f1, field_->MakeOne()));

    auto f2 = field_->Rand();
    EXPECT_TRUE(field_->Equal(f2, f2));
    EXPECT_FALSE(field_->Equal(f1, f2));
  }

  void TestArithmetic() {
    // GIVEN
    auto f1 = field_->Rand();
    auto f2 = field_->Rand();

    // THEN
    // Add, AddInplace
    auto add_ret = field_->Add(f1, f2);
    EXPECT_TRUE(field_->Equal(add_ret, field_->Add(f2, f1)));
    auto temp = field_->Copy(f1);
    field_->AddInplace(&temp, f2);
    EXPECT_TRUE(field_->Equal(add_ret, temp));

    // Neg & Sub, SubInplace
    EXPECT_TRUE(field_->IsZero(field_->Add(f1, field_->Neg(f1))));
    auto sub_ret = field_->Sub(f1, f2);
    EXPECT_TRUE(field_->Equal(sub_ret, field_->Add(f1, field_->Neg(f2))));
    temp = field_->Copy(f1);
    field_->SubInplace(&temp, f2);
    EXPECT_TRUE(field_->Equal(sub_ret, temp));

    // Mul, MulInplace
    auto mul_ret = field_->Mul(f1, f2);
    EXPECT_TRUE(field_->Equal(mul_ret, field_->Mul(f2, f1)));
    temp = field_->Copy(f1);
    field_->MulInplace(&temp, f2);
    EXPECT_TRUE(field_->Equal(mul_ret, temp));

    // Sqr & Pow, PowInplace
    EXPECT_TRUE(field_->Equal(field_->Sqr(f1), field_->Mul(f1, f1)));
    auto pow_temp = field_->MakeOne();
    for (int i = 0; i < 10; i++) {
      auto y = MPInt(i);
      auto pow_ret = field_->Pow(f1, y);
      temp = field_->Copy(f1);
      field_->PowInplace(&temp, y);
      EXPECT_TRUE(field_->Equal(temp, pow_ret));
      EXPECT_TRUE(field_->Equal(pow_ret, pow_temp));

      pow_temp = field_->Mul(temp, f1);
    }

    // Div, DivInplace & Inv
    EXPECT_TRUE(field_->IsOne(field_->Div(f1, f1)));
    auto div_ret = field_->Div(f1, f2);
    temp = field_->Copy(f1);
    field_->DivInplace(&temp, f2);
    EXPECT_TRUE(field_->Equal(temp, div_ret));
    EXPECT_TRUE(
        field_->IsOne(field_->Mul(field_->Div(f1, f2), field_->Div(f2, f1))));
    EXPECT_TRUE(field_->IsOne(field_->Mul(f1, field_->Inv(f1))));
  }

  void TestOrder() {
    auto order = field_->GetOrder();
    // For Fp^n, any element x * order = 0, any element x(!=0)^(order -1) = 1
    for (int i = 0; i < 10; i++) {
      auto f = field_->Rand();
      auto f_pow_order = field_->Pow(f, order);
      EXPECT_TRUE(field_->Equal(f_pow_order, f));
    }
  }

  void TestSerialize() {
    for (int i = 0; i < 1; i++) {
      auto f = field_->Rand();
      // Serialize
      auto buf = field_->Serialize(f);
      auto f1 = field_->Deserialize(buf);
      EXPECT_TRUE(field_->Equal(f, f1));
      // toString
      auto str = field_->ToString(f);
      auto f2 = field_->FromString(str);
      EXPECT_TRUE(field_->Equal(f, f2));
      // ToDecString
      auto str10 = field_->ToDecString(f);
      auto f3 = field_->FromDecString(str10);
      EXPECT_TRUE(field_->Equal(f, f3));
      // ToHexString
      auto str16 = field_->ToHexString(f);
      auto f4 = field_->FromHexString(str16);
      EXPECT_TRUE(field_->Equal(f, f4));
    }
  }
};

#ifdef MCL_FIELD_YACL_TEST
#define DEFAULT_FIELD_TEST(intern_type, degree)                         \
  class Mcl##intern_type##Test : public MclFieldTest {                  \
    void SetUp() override {                                             \
      auto child_ptr = std::make_unique<MclField<intern_type, degree>>( \
          "0xffffffffffffffffffffffffffffffffffffffffffffff13"_mp,      \
          mcl::fp::FP_AUTO);                                            \
      field_ = std::move(child_ptr);                                    \
      filed_name_ = #intern_type;                                       \
    }                                                                   \
  };                                                                    \
  TEST_F(Mcl##intern_type##Test, Works) { RunAllTests(); }

using DefaultFp = mcl::FpT<>;
using DefaultFpWithSize256 = mcl::FpT<mcl::FpTag, 256>;
using DefaultFp2 = mcl::Fp2T<mcl::FpT<>>;
using DefaultFp6 = mcl::Fp6T<mcl::FpT<>>;
using DefaultFp12 = mcl::Fp12T<mcl::FpT<>>;

DEFAULT_FIELD_TEST(DefaultFp, 1);
DEFAULT_FIELD_TEST(DefaultFpWithSize256, 1);
DEFAULT_FIELD_TEST(DefaultFp2, 2);
DEFAULT_FIELD_TEST(DefaultFp6, 6);
DEFAULT_FIELD_TEST(DefaultFp12, 12);
#endif

// TODO: temporarily disable mcl pairing test, since its weird error on Intel
// Mac
#define DECLARE_PAIRING_FIELD_TEST_CLASS(classname, pairing_name) \
  class MclPairing##classname##GTTest : public MclFieldTest {     \
    void SetUp() override {                                       \
      auto pairing = MclPGFactory::CreateByName(pairing_name);    \
      field_ = pairing->GetGT();                                  \
      filed_name_ = "MclPairing" #classname "GTField";            \
      is_sub_field_ = true;                                       \
    }                                                             \
  };                                                              \
  TEST_F(MclPairing##classname##GTTest, DISABLED_Works) { RunAllTests(); }

DECLARE_PAIRING_FIELD_TEST_CLASS(Bls12381, "bls12-381");

#ifdef MCL_ALL_PAIRING_FOR_YACL
DECLARE_PAIRING_FIELD_TEST_CLASS(BN254, "bn254");
DECLARE_PAIRING_FIELD_TEST_CLASS(BN384M, "bn382m");
DECLARE_PAIRING_FIELD_TEST_CLASS(BN384R, "bn382r");
DECLARE_PAIRING_FIELD_TEST_CLASS(BN462, "bn462");
DECLARE_PAIRING_FIELD_TEST_CLASS(BNSnark, "bn_snark1");
DECLARE_PAIRING_FIELD_TEST_CLASS(BN160, "bn160");
DECLARE_PAIRING_FIELD_TEST_CLASS(Bls12461, "bls12-461");
DECLARE_PAIRING_FIELD_TEST_CLASS(BN256, "bn256");
#endif

}  // namespace yacl::crypto::hmcl::test
