// Copyright 2019 Ant Group Co., Ltd.
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

#include "yasl/crypto/drbg/entropy_source_selector.h"

#include <future>
#include <random>
#include <string>
#include <vector>

#include "absl/strings/escaping.h"
#include "gtest/gtest.h"

namespace yasl::crypto {

// Entropy from RNG
TEST(EntropySourceTest, TestWithRNGEntropy) {
  auto entropy_source = makeEntropySource();

  // get string
  std::string entropy_str1 = entropy_source->GetEntropy(128);
  std::string entropy_str2 = entropy_source->GetEntropy(128);

  EXPECT_NE(entropy_str1, entropy_str2);

  // get uint64
  uint64_t entropy_u64_1 = entropy_source->GetEntropy();
  uint64_t entropy_u64_2 = entropy_source->GetEntropy();

  EXPECT_NE(entropy_u64_1, entropy_u64_2);
}

}  // namespace yasl::crypto
