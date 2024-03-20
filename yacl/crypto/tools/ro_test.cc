// Copyright 2021 Ant Group Co., Ltd.
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

#include "yacl/crypto/tools/ro.h"

#include <random>
#include <string>

#include "gtest/gtest.h"

#include "yacl/base/byte_container_view.h"
#include "yacl/base/exception.h"
#include "yacl/crypto/rand/rand.h"

namespace yacl::crypto {

class RandomOracleTest : public testing::TestWithParam<size_t> {};

INSTANTIATE_TEST_SUITE_P(VarInputLen, RandomOracleTest,
                         testing::Values(0, 1, 8, 16, 32, 1024));

TEST_P(RandomOracleTest, Default) {
  const auto& param = GetParam();
  const auto& RO = RandomOracle::GetDefault();
  auto input = FastRandBytes(param);
  EXPECT_EQ(RO.Gen(input), RO.Gen(input));
}

TEST_P(RandomOracleTest, OutLen8) {
  const auto& param = GetParam();
  auto RO = RandomOracle(HashAlgorithm::BLAKE3, 8);
  auto input = FastRandBytes(param);
  EXPECT_EQ(RO.Gen(input), RO.Gen(input));
}

TEST(RandomOracleTest, EdgeTest1) {
  EXPECT_THROW(RandomOracle(HashAlgorithm::BLAKE3, 0), yacl::EnforceNotMet);
}

TEST(RandomOracleTest, EdgeTest2) {
  EXPECT_THROW(RandomOracle(HashAlgorithm::BLAKE3, 33);, yacl::EnforceNotMet);
}

TEST(RandomOracleTest, EdgeTest3) {
  EXPECT_THROW(RandomOracle(HashAlgorithm::BLAKE2B, 65);, yacl::EnforceNotMet);
}

template <typename T>
void inline CheckType(const RandomOracle& ro, ByteContainerView input) {
  EXPECT_EQ(ro.Gen<T>(input), ro.Gen<T>(input));
}

TEST_P(RandomOracleTest, GetTypeTest) {
  const auto& param = GetParam();
  const auto& RO = RandomOracle::GetDefault();
  auto input = FastRandBytes(param);
  CheckType<uint128_t>(RO, input);
  CheckType<int128_t>(RO, input);
  CheckType<uint64_t>(RO, input);
  CheckType<int64_t>(RO, input);
  CheckType<uint32_t>(RO, input);
  CheckType<int32_t>(RO, input);
  CheckType<uint8_t>(RO, input);
  CheckType<int8_t>(RO, input);
  CheckType<bool>(RO, input);
}

TEST_P(RandomOracleTest, TwoParamTest) {
  const auto& param = GetParam();
  const auto& RO = RandomOracle::GetDefault();
  auto input_bytes = FastRandBytes(param);
  auto input_u64 = FastRandU64();

  EXPECT_EQ(RO.Gen<uint128_t>(input_bytes, input_u64),
            RO.Gen<uint128_t>(input_bytes, input_u64));
}

}  // namespace yacl::crypto
