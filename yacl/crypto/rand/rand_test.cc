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

#include <algorithm>
#include <cstring>
#include <limits>

#include "gtest/gtest.h"

#include "yacl/base/int128.h"
#include "yacl/crypto/block_cipher/symmetric_crypto.h"

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

TEST(GenericRandTest, RandLtnTest) {
  {
    uint8_t mersenne_prime = 127;
    auto rand = RandLtN(mersenne_prime);
    EXPECT_TRUE(rand < mersenne_prime);
  }
  {
    uint32_t mersenne_prime = 2147483647;
    auto rand = RandLtN(mersenne_prime);
    EXPECT_TRUE(rand < mersenne_prime);
  }
  {
    uint64_t mersenne_prime = 2305843009213693951;
    auto rand = RandLtN(mersenne_prime);
    EXPECT_TRUE(rand < mersenne_prime);
  }
  {
    uint64_t u64max = std::numeric_limits<uint64_t>::max();
    // should be 170141183460469231731687303715884105727
    uint128_t mersenne_prime = MakeUint128(u64max >> 1, u64max);
    auto rand = RandLtN(mersenne_prime);
    EXPECT_TRUE(rand < mersenne_prime);
  }
}

TEST(GenericRandTest, RandomShuffleTest) {
  auto vec = FastRandVec<uint128_t>(129);
  YaclStdUrbg<uint32_t> g;
  std::shuffle(vec.begin(), vec.end(), g);
}

TEST(GenericRandTest, ReplayRandomShuffleTest) {
  int n = 129;
  auto vec = FastRandVec<uint128_t>(n);

  // same drbg internal states
  {
    auto seed = SecureRandSeed();
    auto ctr = FastRandU64();
    auto iv = FastRandU64();
    auto ctype = yacl::crypto::SymmetricCrypto::CryptoType::AES128_CTR;
    auto vec_copy = vec;

    YaclReplayUrbg<uint32_t> g1(seed, ctr, iv, ctype);
    std::shuffle(vec.begin(), vec.end(), g1);

    YaclReplayUrbg<uint32_t> g2(seed, ctr, iv, ctype);
    std::shuffle(vec_copy.begin(), vec_copy.end(), g2);

    EXPECT_EQ(std::memcmp(vec.data(), vec_copy.data(), sizeof(uint128_t) * n),
              0);
  }

  // different drbg internal states (seed)
  {
    auto seed = SecureRandSeed();
    auto ctr = FastRandU64();
    auto iv = FastRandU64();
    auto ctype = yacl::crypto::SymmetricCrypto::CryptoType::AES128_ECB;
    auto vec1 = vec;
    auto vec2 = vec;
    auto vec3 = vec;
    auto vec4 = vec;

    YaclReplayUrbg<uint32_t> g1(seed, ctr, iv, ctype);
    std::shuffle(vec1.begin(), vec1.end(), g1);

    // different seed will almost always result in different shuffles
    YaclReplayUrbg<uint32_t> g2(seed + 1, ctr, iv, ctype);
    std::shuffle(vec2.begin(), vec2.end(), g2);

    // NOTE g.GetCounter() will return the after-shuffle prg counter
    YaclReplayUrbg<uint32_t> g3(seed, g1.GetCounter() + 1, iv, ctype);
    std::shuffle(vec3.begin(), vec3.end(), g3);

    // NOTE different iv does not gurantee different shuffle, it's
    // recommended to use different seed to generate different shuffles
    YaclReplayUrbg<uint32_t> g4(seed, ctr, iv + 1, ctype);
    std::shuffle(vec4.begin(), vec4.end(), g4);

    // g1 is a random shuffle, different from the original vector
    EXPECT_NE(std::memcmp(vec.data(), vec1.data(), sizeof(uint128_t) * n), 0);

    // g2 is a different shuffle as g1
    EXPECT_NE(std::memcmp(vec.data(), vec2.data(), sizeof(uint128_t) * n), 0);
    EXPECT_NE(std::memcmp(vec1.data(), vec2.data(), sizeof(uint128_t) * n), 0);

    // g3 is a different shuffle as g1
    EXPECT_NE(std::memcmp(vec.data(), vec3.data(), sizeof(uint128_t) * n), 0);
    EXPECT_NE(std::memcmp(vec1.data(), vec3.data(), sizeof(uint128_t) * n), 0);

    // NOTE g4 is a SAME shuffle as g1!!!! even though they differ in iv
    EXPECT_NE(std::memcmp(vec.data(), vec4.data(), sizeof(uint128_t) * n), 0);
    EXPECT_EQ(std::memcmp(vec1.data(), vec4.data(), sizeof(uint128_t) * n), 0);
  }
}
}  // namespace yacl::crypto
