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

#include "yacl/crypto/base/drbg/sm4_drbg.h"

#include <future>
#include <random>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/escaping.h"
#include "absl/types/span.h"
#include "gtest/gtest.h"

#include "yacl/crypto/base/drbg/entropy_source_selector.h"

namespace yacl::crypto {

TEST(GmSm4DrbgTest, TestGenerate) {
  Sm4Drbg drbg;

  std::vector<uint8_t> add_input(8);
  drbg.Instantiate(add_input);
  std::vector<uint8_t> random_buf1 = drbg.Generate(16, add_input);
  std::vector<uint8_t> random_buf2 = drbg.Generate(16, add_input);

  EXPECT_NE(random_buf1, random_buf2);
}

TEST(GmSm4DrbgTest, TestFillPRand) {
  Sm4Drbg drbg;

  std::vector<uint8_t> add_input(8);
  drbg.Instantiate(add_input);
  std::vector<uint8_t> random_buf1(80);
  std::vector<uint8_t> random_buf2(80);
  drbg.FillPRand(absl::MakeSpan(random_buf1));
  drbg.FillPRand(absl::MakeSpan(random_buf2));

  EXPECT_NE(random_buf1, random_buf2);
}

TEST(GmSm4DrbgTest, TestEntropySource) {
  auto entropy_source = makeEntropySource();

  Sm4Drbg drbg(std::move(entropy_source));

  std::vector<uint8_t> add_input(8);
  drbg.Instantiate(add_input);
  std::vector<uint8_t> random_buf1(80);
  std::vector<uint8_t> random_buf2(80);
  drbg.FillPRand(absl::MakeSpan(random_buf1));
  drbg.FillPRand(absl::MakeSpan(random_buf2));

  EXPECT_NE(random_buf1, random_buf2);
}

}  // namespace yacl::crypto
