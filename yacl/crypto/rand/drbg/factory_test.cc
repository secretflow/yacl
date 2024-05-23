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

#include "yacl/base/byte_container_view.h"
#include "yacl/crypto/rand/drbg/drbg.h"

namespace yacl::crypto {

TEST(OpensslTest, CtrDrbgWorks) {
  auto drbg = DrbgFactory::Instance().Create("ctr-drbg");

  std::vector<char> out1(8);
  std::vector<char> out2(8);
  drbg->Fill(out1.data(), 8);
  drbg->Fill(out2.data(), 8);

  // should be different
  EXPECT_NE(std::memcmp(out1.data(), out2.data(), 8), 0);
}

TEST(OpensslTest, HashDrbgWorks) {
  auto drbg = DrbgFactory::Instance().Create("hash-drbg");

  std::vector<char> out1(8);
  std::vector<char> out2(8);
  drbg->Fill(out1.data(), 8);
  drbg->Fill(out2.data(), 8);

  // should be different
  EXPECT_NE(std::memcmp(out1.data(), out2.data(), 8), 0);
}

TEST(OpensslTest, HmacDrbgWorks) {
  auto drbg = DrbgFactory::Instance().Create("hmac-drbg");

  std::vector<char> out1(8);
  std::vector<char> out2(8);
  drbg->Fill(out1.data(), 8);
  drbg->Fill(out2.data(), 8);

  // should be different
  EXPECT_NE(std::memcmp(out1.data(), out2.data(), 8), 0);
}

TEST(NativeTest, GmDrbgWorks) {
  auto drbg = DrbgFactory::Instance().Create("gm-drbg");

  std::vector<char> out1(8);
  std::vector<char> out2(8);
  drbg->Fill(out1.data(), 8);
  drbg->Fill(out2.data(), 8);

  // should be different
  EXPECT_NE(std::memcmp(out1.data(), out2.data(), 8), 0);
}

// TEST(OpensslTest, IcDrbgSameSeedSameResults) {
//   auto drbg1 = DrbgFactory::Instance().Create("IC-HASH-DRBG");
//   auto drbg2 = DrbgFactory::Instance().Create("IC-HASH-DRBG");

//   std::vector<char> out1(8);
//   std::vector<char> out2(8);

//   // set seed
//   drbg1->SetSeed(123);
//   drbg2->SetSeed(123);

//   drbg1->Fill(out1.data(), 8);
//   drbg2->Fill(out2.data(), 8);

//   // should be same
//   EXPECT_NE(std::memcmp(out1.data(), out2.data(), 8), 1);

//   drbg1->Fill(out1.data(), 8);
//   drbg2->Fill(out2.data(), 8);

//   // should be same
//   EXPECT_NE(std::memcmp(out1.data(), out2.data(), 8), 1);
// }

// TEST(OpensslTest, IcDrbgDiffSeedDiffResults) {
//   auto drbg1 = DrbgFactory::Instance().Create("IC-HASH-DRBG");
//   auto drbg2 = DrbgFactory::Instance().Create("IC-HASH-DRBG");

//   std::vector<char> out1(8);
//   std::vector<char> out2(8);

//   // set seed
//   drbg1->SetSeed(123);
//   drbg2->SetSeed(124);

//   drbg1->Fill(out1.data(), 8);
//   drbg2->Fill(out2.data(), 8);

//   // should be different
//   EXPECT_NE(std::memcmp(out1.data(), out2.data(), 8), 0);

//   drbg1->Fill(out1.data(), 8);
//   drbg2->Fill(out2.data(), 8);

//   // should be different
//   EXPECT_NE(std::memcmp(out1.data(), out2.data(), 8), 0);
// }

// TEST(OpensslTest, IcDrbgDiffRoundDiffResults) {
//   auto drbg = DrbgFactory::Instance().Create("IC-HASH-DRBG");

//   std::vector<char> out1(8);
//   std::vector<char> out2(8);

//   drbg->SetSeed(123);

//   drbg->Fill(out1.data(), 8);
//   drbg->Fill(out2.data(), 8);

//   // should be different
//   EXPECT_NE(std::memcmp(out1.data(), out2.data(), 8), 0);
// }

}  // namespace yacl::crypto
