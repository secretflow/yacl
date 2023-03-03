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

#include "yacl/crypto/tools/prg.h"

#include <cstdint>
#include <memory>
#include <random>

#include "gtest/gtest.h"

namespace yacl::crypto {
namespace {

constexpr uint128_t kKey1 = 1234;
constexpr uint128_t kKey2 = 2345;

struct Foo {
  uint64_t a;
  char b;
  uint8_t c;
  bool operator==(const Foo& rhs) const {
    return a == rhs.a && b == rhs.b && c == rhs.c;
  }
  bool operator!=(const Foo& rhs) const { return !(*this == rhs); }
};

std::ostream& operator<<(std::ostream& os, const Foo& foo) {
  os << "[ a=" << foo.a << ", b=" << foo.b << ", c=" << foo.c;
  return os;
}

}  // namespace

TEST(Prg, BooleanWorks) {
  // GIVEN
  Prg<bool> prg(kKey1);
  // WHEN
  std::array<int, 2> counts = {0, 0};
  const int kNumCalls = 10000;
  for (int i = 0; i < kNumCalls; ++i) {
    bool index = prg();
    EXPECT_TRUE(index == 0 || index == 1);
    counts[index]++;
  }
  // THEN
  double ratio = counts[0] / static_cast<double>(kNumCalls);
  // Give a loose constraint `5%`
  EXPECT_TRUE(std::abs(ratio - 0.5) <= 0.05) << ratio;
}

TEST(Prg, BuiltinScalarsWorks) {
  {
    // GIVEN
    Prg<int> prg(kKey1);
    // WHEN
    int a = prg();
    int b = prg();
    // THEN
    EXPECT_NE(a, b);
  }

  {
    // GIVEN
    Prg<double> prg(kKey1);
    // WHEN
    double a = prg();
    double b = prg();
    // THEN
    EXPECT_NE(a, b);
  }

  {
    // GIVEN
    Prg<uint64_t> prg(kKey1);
    // WHEN
    uint64_t a = prg();
    uint64_t b = prg();
    // THEN
    EXPECT_NE(a, b);
  }

  {
    // GIVEN
    Prg<uint128_t> prg(kKey1);
    // WHEN
    uint128_t a = prg();
    uint128_t b = prg();
    // THEN
    EXPECT_NE(a, b);
  }
}

TEST(Prg, WorksForCustomizedStruct) {
  // GIVEN
  Prg<Foo> prg(kKey1);
  int ncalls = 3 * decltype(prg)::BatchSize() + 13;
  Foo last = prg();
  for (int i = 0; i < ncalls; ++i) {
    // WHEN
    Foo now = prg();
    // THEN
    EXPECT_NE(now, last);
  }
}

TEST(Prg, DeterministicWithSameSeed) {
  Prg<int> prg1(kKey1);
  Prg<int> prg2(kKey1);
  for (int i = 0; i < 128; ++i) {
    EXPECT_EQ(prg1(), prg2());
    EXPECT_EQ(prg1(), prg2());
  }
}

TEST(Prg, DeterministicWithDifferentSeed) {
  Prg<int> prg1(kKey1);
  Prg<int> prg2(kKey2);
  for (int i = 0; i < 128; ++i) {
    EXPECT_NE(prg1(), prg2());
    EXPECT_NE(prg1(), prg2());
  }
}

TEST(Prg, FillPRandomBytes) {
  constexpr int kSize = 11;
  std::vector<uint8_t> output1(kSize);
  std::vector<uint8_t> output2(kSize);
  auto c1 = FillPRandBytes(SymmetricCrypto::CryptoType::AES128_ECB, 0, 0, 0,
                           absl::MakeSpan(output1));
  auto c2 = FillPRandBytes(SymmetricCrypto::CryptoType::AES128_ECB, 0, 0, c1,
                           absl::MakeSpan(output2));
  const uint128_t expected =
      (kSize + sizeof(uint128_t) - 1) / sizeof(uint128_t);
  EXPECT_EQ(c1, expected);
  EXPECT_EQ(c2, 2 * expected);
  for (int i = 0; i < kSize; ++i) {
    EXPECT_NE(output1[i], output2[i]);
  }
}

TEST(Prg, FillAesRandom) {
  constexpr int kSize = 11;
  std::vector<uint64_t> output1(kSize);
  std::vector<uint64_t> output2(kSize);
  auto c1 = FillPRand(SymmetricCrypto::CryptoType::AES128_ECB, 0, 0, 0,
                      absl::MakeSpan(output1));
  auto c2 = FillPRand(SymmetricCrypto::CryptoType::AES128_ECB, 0, 0, c1,
                      absl::MakeSpan(output2));
  const uint128_t expected =
      (sizeof(uint64_t) * kSize + sizeof(uint128_t) - 1) / sizeof(uint128_t);
  EXPECT_EQ(c1, expected);
  EXPECT_EQ(c2, 2 * expected);
  for (int i = 0; i < kSize; ++i) {
    EXPECT_NE(output1[i], output2[i]);
  }
}

TEST(Prg, DeterministicWithSameSeedSm4) {
  Prg<int> prg1(kKey1, PRG_MODE::KSm4Ecb);
  Prg<int> prg2(kKey1, PRG_MODE::KSm4Ecb);
  for (int i = 0; i < 128; ++i) {
    EXPECT_EQ(prg1(), prg2());
    EXPECT_EQ(prg1(), prg2());
  }
}

TEST(Prg, DeterministicWithDifferentSeedSm4) {
  Prg<int> prg1(kKey1, PRG_MODE::KSm4Ecb);
  Prg<int> prg2(kKey2, PRG_MODE::KSm4Ecb);
  for (int i = 0; i < 128; ++i) {
    EXPECT_NE(prg1(), prg2());
    EXPECT_NE(prg1(), prg2());
  }
}

// nist ase_ctr drbg
TEST(PRandomCtrDrbg, BooleanWorks) {
  // GIVEN
  Prg<bool> prg(kKey1, PRG_MODE::kNistAesCtrDrbg);
  // WHEN
  std::array<int, 2> counts = {0, 0};
  const int kNumCalls = 10000;
  for (int i = 0; i < kNumCalls; ++i) {
    bool index = prg();
    EXPECT_TRUE(index == 0 || index == 1);
    counts[index]++;
  }
  // THEN
  double ratio = counts[0] / static_cast<double>(kNumCalls);
  // Give a loose constraint `5%`
  EXPECT_TRUE(std::abs(ratio - 0.5) <= 0.05) << ratio;
}

TEST(PRandomCtrDrbg, BuiltinScalarsWorks) {
  {
    // GIVEN
    Prg<int> prg(kKey1, PRG_MODE::kNistAesCtrDrbg);
    // WHEN
    int a = prg();
    int b = prg();
    // THEN
    EXPECT_NE(a, b);
  }

  {
    // GIVEN
    Prg<double> prg(kKey1, PRG_MODE::kNistAesCtrDrbg);
    // WHEN
    double a = prg();
    double b = prg();
    // THEN
    EXPECT_NE(a, b);
  }

  {
    // GIVEN
    Prg<uint64_t> prg(kKey1, PRG_MODE::kNistAesCtrDrbg);
    // WHEN
    uint64_t a = prg();
    uint64_t b = prg();
    // THEN
    EXPECT_NE(a, b);
  }

  {
    // GIVEN
    Prg<uint128_t> prg(kKey1, PRG_MODE::kNistAesCtrDrbg);
    // WHEN
    uint128_t a = prg();
    uint128_t b = prg();
    // THEN
    EXPECT_NE(a, b);
  }
}

TEST(PRandomCtrDrbg, WorksForCustomizedStruct) {
  // GIVEN
  Prg<Foo> prg(kKey1, PRG_MODE::kNistAesCtrDrbg);
  int ncalls = 3 * decltype(prg)::BatchSize() + 13;
  Foo last = prg();
  for (int i = 0; i < ncalls; ++i) {
    // WHEN
    Foo now = prg();
    // THEN
    EXPECT_NE(now, last);
  }
}

TEST(PRandomCtrDrbg, DeterministicWithSameSeed) {
  Prg<int> prg1(kKey1, PRG_MODE::kNistAesCtrDrbg);
  Prg<int> prg2(kKey1, PRG_MODE::kNistAesCtrDrbg);
  for (int i = 0; i < 128; ++i) {
    EXPECT_NE(prg1(), prg2());
    EXPECT_NE(prg1(), prg2());
  }
}

TEST(PRandomCtrDrbg, DeterministicWithDifferentSeed) {
  Prg<int> prg1(kKey1, PRG_MODE::kNistAesCtrDrbg);
  Prg<int> prg2(kKey2, PRG_MODE::kNistAesCtrDrbg);
  for (int i = 0; i < 128; ++i) {
    EXPECT_NE(prg1(), prg2());
    EXPECT_NE(prg1(), prg2());
  }
}

// nist gm sm4_ctr drbg
TEST(PRandomSm4Drbg, BooleanWorks) {
  // GIVEN
  Prg<bool> prg(kKey1, PRG_MODE::kGmSm4CtrDrbg);
  // WHEN
  std::array<int, 2> counts = {0, 0};
  const int kNumCalls = 10000;
  for (int i = 0; i < kNumCalls; ++i) {
    bool index = prg();
    EXPECT_TRUE(index == 0 || index == 1);
    counts[index]++;
  }
  // THEN
  double ratio = counts[0] / static_cast<double>(kNumCalls);
  // Give a loose constraint `5%`
  EXPECT_TRUE(std::abs(ratio - 0.5) <= 0.05) << ratio;
}

TEST(PRandomSm4Drbg, BuiltinScalarsWorks) {
  {
    // GIVEN
    Prg<int> prg(kKey1, PRG_MODE::kGmSm4CtrDrbg);
    // WHEN
    int a = prg();
    int b = prg();
    // THEN
    EXPECT_NE(a, b);
  }

  {
    // GIVEN
    Prg<double> prg(kKey1, PRG_MODE::kGmSm4CtrDrbg);
    // WHEN
    double a = prg();
    double b = prg();
    // THEN
    EXPECT_NE(a, b);
  }

  {
    // GIVEN
    Prg<uint64_t> prg(kKey1, PRG_MODE::kGmSm4CtrDrbg);
    // WHEN
    uint64_t a = prg();
    uint64_t b = prg();
    // THEN
    EXPECT_NE(a, b);
  }

  {
    // GIVEN
    Prg<uint128_t> prg(kKey1, PRG_MODE::kGmSm4CtrDrbg);
    // WHEN
    uint128_t a = prg();
    uint128_t b = prg();
    // THEN
    EXPECT_NE(a, b);
  }
}

TEST(PRandomSm4Drbg, WorksForCustomizedStruct) {
  // GIVEN
  Prg<Foo> prg(kKey1, PRG_MODE::kGmSm4CtrDrbg);
  int ncalls = 3 * decltype(prg)::BatchSize() + 13;
  Foo last = prg();
  for (int i = 0; i < ncalls; ++i) {
    // WHEN
    Foo now = prg();
    // THEN
    EXPECT_NE(now, last);
  }
}

TEST(PRandomSm4Drbg, DeterministicWithSameSeed) {
  Prg<int> prg1(kKey1, PRG_MODE::kGmSm4CtrDrbg);
  Prg<int> prg2(kKey1, PRG_MODE::kGmSm4CtrDrbg);
  for (int i = 0; i < 128; ++i) {
    EXPECT_NE(prg1(), prg2());
    EXPECT_NE(prg1(), prg2());
  }
}

TEST(PRandomSm4Drbg, DeterministicWithDifferentSeed) {
  Prg<int> prg1(kKey1, PRG_MODE::kGmSm4CtrDrbg);
  Prg<int> prg2(kKey2, PRG_MODE::kGmSm4CtrDrbg);
  for (int i = 0; i < 128; ++i) {
    EXPECT_NE(prg1(), prg2());
    EXPECT_NE(prg1(), prg2());
  }
}

}  // namespace yacl::crypto
