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

#include "yacl/math/galois_field/gf.h"

#include <cstdint>

#include "gtest/gtest.h"

namespace yacl::math {

TEST(PrimeFieldTest, Works) {
  // Note that: kPrimeField implmentation requires ArgMod
  auto gf = GaloisFieldFactory::Instance().Create(
      kPrimeField,
      ArgMod = "0xffffffffffffffffffffffffffffffffffffffffffffff13"_mp);

  EXPECT_EQ(gf->GetLibraryName(), kMclLib);    // kMclLib has kPrimeField
  EXPECT_EQ(gf->GetFieldName(), kPrimeField);  //
  EXPECT_TRUE(gf->GetExtensionDegree() == 1);  // default = no extension
}

TEST(ExtensionFieldTest, Works) {
  // Note that: kPrimeField implmentation requires ArgDegree and ArgMod
  auto gf = GaloisFieldFactory::Instance().Create(
      kExtensionField, ArgDegree = 2,
      ArgMod = "0xffffffffffffffffffffffffffffffffffffffffffffff13"_mp);

  EXPECT_EQ(gf->GetLibraryName(), kMclLib);  // kMclLib has kExtensionField
  EXPECT_EQ(gf->GetFieldName(), kExtensionField);
  EXPECT_TRUE(gf->GetExtensionDegree() == 2);
}

TEST(BinaryTest, Works) {
  // Note that: kPrimeField implmentation requires ArgDegree
  auto gf = GaloisFieldFactory::Instance().Create(kBinaryField, ArgDegree = 64);

  EXPECT_EQ(gf->GetLibraryName(), kIntelLib);  // kIntelLib has kBinaryField
  EXPECT_EQ(gf->GetFieldName(), kBinaryField);
  EXPECT_TRUE(gf->GetExtensionDegree() == 64);
}

}  // namespace yacl::math
