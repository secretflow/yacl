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

#include "yacl/crypto/rand/entropy_source/entropy_source.h"

namespace yacl::crypto {

namespace {
constexpr size_t kBitOfEntropy = 100;
}

#ifdef __x86_64

TEST(OpensslTest, HardwareESWorks) {
  auto es = EntropySourceFactory::Instance().Create("hardware");
  auto x = es->GetEntropy(kBitOfEntropy);
  auto y = es->GetEntropy(kBitOfEntropy);

  // SPDLOG_INFO(es->Name());

  EXPECT_GE(x.size() * 8, kBitOfEntropy);
  EXPECT_GE(y.size() * 8, kBitOfEntropy);
  EXPECT_EQ(x.size(), y.size());
  EXPECT_FALSE(x == y);
}

#endif

TEST(OpensslTest, SoftwareESWorks) {
  auto es = EntropySourceFactory::Instance().Create("software");
  auto x = es->GetEntropy(kBitOfEntropy);
  auto y = es->GetEntropy(kBitOfEntropy);

  // SPDLOG_INFO(es->Name());

  EXPECT_GE(x.size() * 8, kBitOfEntropy);
  EXPECT_GE(y.size() * 8, kBitOfEntropy);
  EXPECT_EQ(x.size(), y.size());
  EXPECT_FALSE(x == y);
}

TEST(OpensslTest, AutoESWorks) {
  auto es = EntropySourceFactory::Instance().Create("auto");
  auto x = es->GetEntropy(kBitOfEntropy);
  auto y = es->GetEntropy(kBitOfEntropy);

  // SPDLOG_INFO(es->Name());

  EXPECT_GE(x.size() * 8, kBitOfEntropy);
  EXPECT_GE(y.size() * 8, kBitOfEntropy);
  EXPECT_EQ(x.size(), y.size());
  EXPECT_FALSE(x == y);
}

}  // namespace yacl::crypto
