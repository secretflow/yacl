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
constexpr size_t kTestSize = 10;
}

#ifdef __x86_64

TEST(OpensslTest, HardwareESWorks) {
  auto es = EntropySourceFactory::Instance().Create("hardware");
  auto x = es->GetEntropy(kTestSize);
  auto y = es->GetEntropy(kTestSize);

  // SPDLOG_INFO(es->Name());

  EXPECT_NE(std::memcmp(x.data(), y.data(), kTestSize), 0);
}

#endif

TEST(OpensslTest, SoftwareESWorks) {
  auto es = EntropySourceFactory::Instance().Create("software");
  auto x = es->GetEntropy(kTestSize);
  auto y = es->GetEntropy(kTestSize);

  // SPDLOG_INFO(es->Name());

  EXPECT_NE(std::memcmp(x.data(), y.data(), kTestSize), 0);
}

TEST(OpensslTest, AutoESWorks) {
  auto es = EntropySourceFactory::Instance().Create("auto");
  auto x = es->GetEntropy(kTestSize);
  auto y = es->GetEntropy(kTestSize);

  SPDLOG_INFO(es->Name());

  EXPECT_NE(std::memcmp(x.data(), y.data(), kTestSize), 0);
}

}  // namespace yacl::crypto
