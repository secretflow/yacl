// Copyright 2022 Ant Group Co., Ltd.
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

#include <random>

#include "fmt/format.h"
#include "gtest/gtest.h"

#include "yacl/crypto/base/mpint/tommath_ext_features.h"
#include "yacl/utils/scope_guard.h"

namespace yacl::crypto::test {

#define MP_ASSERT_OK(MP_ERR) EXPECT_EQ((MP_ERR), MP_OKAY)

std::string Info(const mp_int& n) {
  int size = 0;
  MP_ASSERT_OK(mp_radix_size(&n, 16, &size));

  std::string output;
  output.resize(size);
  MP_ASSERT_OK(mp_to_radix(&n, output.data(), size, nullptr, 16));
  output.pop_back();  // remove tailing '\0'
  return fmt::format("[used={}, bits={}, dp={}]", n.used, mp_count_bits(&n),
                     output);
}

TEST(TommathExtTest, CountBits) {
  mp_int n;
  MP_ASSERT_OK(mp_init_i32(&n, 0));
  ON_SCOPE_EXIT([&] { mp_clear(&n); });
  EXPECT_EQ(mp_ext_count_bits_fast(n), 0);

  MP_ASSERT_OK(mp_incr(&n));
  EXPECT_EQ(mp_ext_count_bits_fast(n), 1);

  for (int i = 0; i < 4096; ++i) {
    MP_ASSERT_OK(mp_mul_2(&n, &n));
    EXPECT_EQ(mp_ext_count_bits_fast(n), mp_count_bits(&n));
  }

  mp_zero(&n);
  MP_ASSERT_OK(mp_incr(&n));
  for (int i = 0; i < 128; ++i) {
    EXPECT_EQ(mp_ext_count_bits_fast(n), i + 1) << Info(n);
    MP_ASSERT_OK(mp_mul_2(&n, &n));
    if (i % 2 == 1) {
      MP_ASSERT_OK(mp_incr(&n));
    }
  }
}

TEST(TommathExtTest, CountBitsRandom) {
  mp_int n;
  MP_ASSERT_OK(mp_init_i64(&n, 0));
  ON_SCOPE_EXIT([&] { mp_clear(&n); });
  EXPECT_EQ(mp_ext_count_bits_fast(n), 0);

  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<uint64_t> dis;
  for (int64_t i = 0; i < 10000000; ++i) {
    uint64_t a = dis(gen) & MP_MASK;
    mp_set_u64(&n, a);
    int bits = 0;
    while (a > 0) {
      ++bits;
      a >>= 1;
    }

    EXPECT_EQ(mp_ext_count_bits_fast(n), bits) << Info(n);
  }

  for (int64_t i = 0; i < 1000000; ++i) {
    uint64_t a = dis(gen);
    mp_set_u64(&n, a);
    int bits = 0;
    while (a > 0) {
      ++bits;
      a >>= 1;
    }

    EXPECT_EQ(mp_ext_count_bits_fast(n), bits) << Info(n);
  }
}

TEST(TommathExtTest, Serialize) {
  unsigned char buf[20000];
  mp_int a;
  MP_ASSERT_OK(mp_init(&a));
  ON_SCOPE_EXIT([&] { mp_clear(&a); });
  mp_int b;
  MP_ASSERT_OK(mp_init(&b));
  ON_SCOPE_EXIT([&] { mp_clear(&b); });

  for (int64_t bits = 0; bits < 4097; ++bits) {
    for (int64_t i = 0; i < 100; ++i) {
      mp_ext_rand_bits(&a, bits);
      if (i % 2 == 0) {
        MP_ASSERT_OK(mp_neg(&a, &a));
      }
      auto sz = mp_ext_serialize_size(a);
      mp_ext_serialize(a, buf, sz);

      mp_ext_deserialize(&b, buf, sz);
      ASSERT_EQ(mp_cmp(&a, &b), 0)
          << "a is " << Info(a) << "\nb is " << Info(b);
    }
  }
}

TEST(TommathExtTest, GetBit) {
  uint64_t s = 0x78541254;
  mp_int n;
  MP_ASSERT_OK(mp_init_u64(&n, s));
  ON_SCOPE_EXIT([&] { mp_clear(&n); });

  mp_int new_n;
  MP_ASSERT_OK(mp_init(&new_n));
  ON_SCOPE_EXIT([&] { mp_clear(&new_n); });

  int idx = 0;
  while (s != 0) {
    EXPECT_EQ(s & 1, mp_ext_get_bit(n, idx));
    mp_ext_set_bit(&new_n, idx, s & 1);
    s >>= 1;
    ++idx;
  }

  EXPECT_TRUE(mp_cmp(&n, &new_n) == 0);
  mp_ext_set_bit(&new_n, 666, 0);
  EXPECT_TRUE(mp_cmp(&n, &new_n) == 0);

  mp_ext_set_bit(&new_n, 1000, 1);
  EXPECT_EQ(mp_ext_get_bit(new_n, 999), 0);
  EXPECT_EQ(mp_ext_get_bit(new_n, 1000), 1);
  EXPECT_EQ(mp_ext_get_bit(new_n, 1001), 0);
  EXPECT_EQ(mp_ext_count_bits_fast(new_n), 1001);

  mp_ext_set_bit(&new_n, 1000, 0);
  EXPECT_EQ(mp_ext_get_bit(new_n, 1000), 0);
  EXPECT_LE(mp_ext_count_bits_fast(new_n), 64);
}

}  // namespace yacl::crypto::test
