// Copyright 2023 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "yacl/math/galois_field/factory/intel_factory.h"

#include <cstdint>

#include "gtest/gtest.h"

namespace yacl::math::test {

TEST(IntrinsicFieldTest, Basic64Works) {
  auto gf = GaloisFieldFactory::Instance().Create(kBinaryField, ArgDegree = 64);

  EXPECT_EQ(gf->GetLibraryName(), kIntelLib);
  EXPECT_EQ(gf->GetFieldName(), kBinaryField);

  EXPECT_TRUE(gf->GetExtensionDegree() == 64);
  EXPECT_TRUE((bool)gf->IsIdentityZero(gf->GetIdentityZero()));
  EXPECT_TRUE((bool)gf->IsIdentityOne(gf->GetIdentityOne()));
}

TEST(IntrinsicFieldTest, Basic128Works) {
  auto gf =
      GaloisFieldFactory::Instance().Create(kBinaryField, ArgDegree = 128);

  EXPECT_EQ(gf->GetLibraryName(), kIntelLib);
  EXPECT_EQ(gf->GetFieldName(), kBinaryField);

  EXPECT_TRUE(gf->GetExtensionDegree() == 128);
  EXPECT_TRUE((bool)gf->IsIdentityZero(gf->GetIdentityZero()));
  EXPECT_TRUE((bool)gf->IsIdentityOne(gf->GetIdentityOne()));
}

TEST(IntrinsicFieldTest, Scalar64Works) {
  auto gf = GaloisFieldFactory::Instance().Create(kBinaryField, ArgDegree = 64);
  using T = uint64_t;

  EXPECT_TRUE((bool)gf->IsIdentityZero(T(0)));
  EXPECT_FALSE((bool)gf->IsIdentityZero(T(1)));
  EXPECT_FALSE((bool)gf->IsIdentityOne(T(0)));
  EXPECT_TRUE((bool)gf->IsIdentityOne(T(1)));

  EXPECT_TRUE((bool)gf->IsInField(T(0)));
  EXPECT_TRUE((bool)gf->IsInField(T(1)));
  EXPECT_TRUE((bool)gf->IsInField(T(12)));

  EXPECT_TRUE((bool)gf->Equal(T(0), T(0)));
  EXPECT_FALSE((bool)gf->Equal(T(1), T(0)));
  EXPECT_TRUE((bool)gf->Equal(T(12), T(12)));

  // operands //
  const auto x = gf->Random();
  const auto y = gf->Random();
  const auto kOne = gf->GetIdentityOne();
  const auto kZero = gf->GetIdentityZero();

#define EXPECT_FIELD_EQ(x, y) EXPECT_EQ(x.As<T>(), y.As<T>())
  // neg
  EXPECT_FIELD_EQ(x, gf->Neg(gf->Neg(x)));
  EXPECT_FIELD_EQ(kZero, gf->Neg(kZero));

  // inv
  EXPECT_FIELD_EQ(x, gf->Inv(gf->Inv(x)));
  EXPECT_FIELD_EQ(gf->Inv(kOne), kOne);
  EXPECT_ANY_THROW(gf->Inv(kZero));  // error

  // +, -
  EXPECT_FIELD_EQ(gf->Add(x, y), gf->Add(y, x));
  EXPECT_FIELD_EQ(gf->Add(x, gf->Neg(y)), gf->Sub(x, y));

  // mul, div
  const auto z = gf->Mul(x, y);
  EXPECT_FIELD_EQ(gf->Mul(x, kOne), x);
  EXPECT_FIELD_EQ(gf->Mul(gf->Inv(x), x), kOne);
  EXPECT_FIELD_EQ(gf->Div(z, y), x);
  EXPECT_FIELD_EQ(gf->Div(z, x), y);
  EXPECT_FIELD_EQ(gf->Inv(x), gf->Div(kOne, x));
#undef EXPECT_FIELD_EQ
}

TEST(IntrinsicFieldTest, Scalar128Works) {
  auto gf =
      GaloisFieldFactory::Instance().Create(kBinaryField, ArgDegree = 128);
  using T = uint128_t;

  EXPECT_TRUE((bool)gf->IsIdentityZero(T(0)));
  EXPECT_FALSE((bool)gf->IsIdentityZero(T(1)));
  EXPECT_FALSE((bool)gf->IsIdentityOne(T(0)));
  EXPECT_TRUE((bool)gf->IsIdentityOne(T(1)));

  EXPECT_TRUE((bool)gf->IsInField(T(0)));
  EXPECT_TRUE((bool)gf->IsInField(T(1)));
  EXPECT_TRUE((bool)gf->IsInField(T(12)));

  EXPECT_TRUE((bool)gf->Equal(T(0), T(0)));
  EXPECT_FALSE((bool)gf->Equal(T(1), T(0)));
  EXPECT_TRUE((bool)gf->Equal(T(12), T(12)));

  // operands //
  const auto x = gf->Random();
  const auto y = gf->Random();
  const auto kOne = gf->GetIdentityOne();
  const auto kZero = gf->GetIdentityZero();

#define EXPECT_FIELD_EQ(x, y) EXPECT_EQ(x.As<T>(), y.As<T>())
  // neg
  EXPECT_FIELD_EQ(x, gf->Neg(gf->Neg(x)));
  EXPECT_FIELD_EQ(kZero, gf->Neg(kZero));

  // inv
  // EXPECT_FIELD_EQ(x, gf->Inv(gf->Inv(x)));
  // EXPECT_FIELD_EQ(gf->Inv(kOne), kOne);
  EXPECT_ANY_THROW(gf->Inv(kZero));  // error

  // +, -
  EXPECT_FIELD_EQ(gf->Add(x, y), gf->Add(y, x));
  EXPECT_FIELD_EQ(gf->Add(x, gf->Neg(y)), gf->Sub(x, y));

  // mul, div
  const auto z = gf->Mul(x, y);
  EXPECT_FIELD_EQ(gf->Mul(x, kOne), x);
  // EXPECT_FIELD_EQ(gf->Mul(gf->Inv(x), x), kOne);
  // EXPECT_FIELD_EQ(gf->Div(z, y), x);
  // EXPECT_FIELD_EQ(gf->Div(z, x), y);
  // EXPECT_FIELD_EQ(gf->Inv(x), gf->Div(kOne, x));
#undef EXPECT_FIELD_EQ
}
}  // namespace yacl::math::test
