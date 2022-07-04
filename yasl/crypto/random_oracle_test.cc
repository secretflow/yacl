// Copyright 2022 Ant Group Co., Ltd.
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


#include "yasl/crypto/random_oracle.h"

#include <random>

#include "gtest/gtest.h"

#include "yasl/utils/hamming.h"

namespace yasl {

inline size_t HammingDistance(absl::Span<const uint128_t> x,
                              absl::Span<const uint128_t> y) {
  YASL_ENFORCE_EQ(x.size(), y.size());
  size_t sum = 0;
  for (size_t i = 0; i < x.size(); ++i) {
    sum += HammingDistance(x[i], y[i]);
  }
  return sum;
}

// Reference: https://eprint.iacr.org/2016/799.pdf
//
// See `Pseudorandom codes` in Charpter II. Which guarantees the hamming
// distance between two random oracles output is guaranteed to be at least 128
// bits when we have `512` bits output width.
TEST(RandomOracle, KkrtHammingDistanceProof) {
  // GIVEN
  const size_t kKkrtWidth = 4;
  RandomOracle ro(SymmetricCrypto::CryptoType::AES128_CBC, 9527);
  // WHEN
  const int kNum = 1000;
  std::vector<std::array<uint128_t, kKkrtWidth>> items;
  size_t total_hamming_distance = 0;
  size_t hamming_count = 0;
  size_t min_distance = std::numeric_limits<size_t>::max();
  std::random_device rd;
  for (int i = 0; i < kNum; ++i) {
    items.push_back(ro.Gen<kKkrtWidth>(rd()));
    for (size_t k = 0; k < items.size() - 1; ++k) {
      size_t distance = HammingDistance(items[k], items.back());
      total_hamming_distance += distance;
      hamming_count++;
      min_distance = std::min(distance, min_distance);
    }
  }
  // THEN
  double mean_distance =
      static_cast<double>(total_hamming_distance) / hamming_count;
  EXPECT_GE(mean_distance, 128) << mean_distance;
  EXPECT_GE(min_distance, 128) << min_distance;
  std::cout << "mean_hamming_distance=" << mean_distance << std::endl;
  std::cout << "min_hamming_distance=" << min_distance << std::endl;
}

TEST(RandomOracle, AutoOutputTypeInference) {
  // GIVEN
  RandomOracle ro(SymmetricCrypto::CryptoType::AES128_CBC, 9527);
  // WHEN, THEN
  uint128_t y = ro.Gen(1234);
  std::array<uint128_t, 5> z = ro.Gen<5>(1234);
  EXPECT_EQ(y, z[0]) << y << ", " << z[0];
}

}  // namespace yasl
