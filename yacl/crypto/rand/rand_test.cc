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

#include "yacl/crypto/rand/rand.h"

#include "gtest/gtest.h"

namespace yacl::crypto {

#define TEST_GENERIC_TYPE_RAND_FUNC(FUNC, ...) \
  TEST(GenericRandTest, Fast##FUNC##Test) {    \
    auto tmp1 = Fast##FUNC(__VA_ARGS__);       \
    auto tmp2 = Fast##FUNC(__VA_ARGS__);       \
                                               \
    /* should be different*/                   \
    EXPECT_TRUE(tmp1 != tmp2);                 \
  }                                            \
                                               \
  TEST(GenericRandTest, Secure##FUNC##Test) {  \
    auto tmp1 = Secure##FUNC(__VA_ARGS__);     \
    auto tmp2 = Secure##FUNC(__VA_ARGS__);     \
                                               \
    /* should be different*/                   \
    EXPECT_TRUE(tmp1 != tmp2);                 \
  }

TEST_GENERIC_TYPE_RAND_FUNC(RandU64);
TEST_GENERIC_TYPE_RAND_FUNC(RandU128);
TEST_GENERIC_TYPE_RAND_FUNC(RandSeed);
TEST_GENERIC_TYPE_RAND_FUNC(RandBytes, 10);
TEST_GENERIC_TYPE_RAND_FUNC(RandBits, 10);

template <typename T>
std::pair<uint64_t, uint64_t> Count(T val) {
  uint64_t zero_num = 0;
  uint64_t one_num = 0;
  size_t num = sizeof(T) * 8;
  for (size_t i = 0; i < num; ++i) {
    val & 0x1 ? ++one_num : ++zero_num;
    val >>= 1;
  }
  return std::make_pair(zero_num, one_num);
}

// \sum_{i=350}^{750}( (1/2)^i (1/2)^{1000-i} (1000 choose i) ) = 0.9999999999
TEST(GenericRandTest, RandBits01Test) {
  auto rand = SecureRandBits(1000);
  int64_t one_num = 0;
  int64_t zero_num = 0;
  for (size_t i = 0; i < 1000; ++i) {
    rand[i] ? ++one_num : ++zero_num;
  }
  auto diff = std::abs(one_num - zero_num);

  EXPECT_TRUE(diff < 300);
}

TEST(GenericRandTest, RandVec01Test) {
  auto vec = RandVec<uint8_t>(125);  // 125 * 8 = 1000
  yacl::dynamic_bitset<uint8_t> rand;
  for (const auto& val : vec) {
    rand.append(val);
  }

  int64_t one_num = 0;
  int64_t zero_num = 0;
  for (size_t i = 0; i < rand.size(); ++i) {
    rand[i] ? ++one_num : ++zero_num;
  }
  auto diff = std::abs(one_num - zero_num);

  EXPECT_TRUE(diff < 300);
}

}  // namespace yacl::crypto
