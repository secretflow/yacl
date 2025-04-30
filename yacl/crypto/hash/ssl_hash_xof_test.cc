// Copyright 2025 Ant Group Co., Ltd.
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

#include "yacl/crypto/hash/ssl_hash_xof.h"

#include "absl/strings/escaping.h"
#include "gtest/gtest.h"

#include "yacl/base/exception.h"

namespace yacl::crypto {

struct TestData {
  std::string input;
  std::string output_128;
  std::string output_256;
};
constexpr size_t kOutputLength128 = 16;
constexpr size_t kOutputLength256 = 32;
constexpr size_t kOutputLength1024 = 128;

// NIST test vectors from:
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHAKE128_Msg0.pdf
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHAKE256_Msg0.pdf
const TestData kTestVectors[] = {
    // Empty input test vector
    {"",
     // SHAKE128 empty input
     "7f9c2ba4e88f827d616045507605853e",
     // SHAKE256
     "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762"
     "f"},
    // "abc" test vector
    {"abc",
     // SHAKE128
     "5881092dd818bf5cf8a3ddb793fbcba7",
     // SHAKE256
     "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b573"
     "9"},
};

TEST(XofHashTest, TestShake128) {
  for (const auto& test : kTestVectors) {
    SslHashXof hash(HashAlgorithm::SHAKE128);
    hash.Update(test.input);

    auto result = hash.CumulativeHash(kOutputLength128);
    EXPECT_EQ(absl::BytesToHexString(
                  absl::string_view((const char*)result.data(), result.size())),
              test.output_128);
  }
}

TEST(XofHashTest, TestShake256) {
  for (const auto& test : kTestVectors) {
    SslHashXof hash(HashAlgorithm::SHAKE256);
    hash.Update(test.input);

    auto result = hash.CumulativeHash(kOutputLength256);
    EXPECT_EQ(absl::BytesToHexString(
                  absl::string_view((const char*)result.data(), result.size())),
              test.output_256);
  }
}

TEST(XofHashTest, TestVariableLength) {
  const auto& test = kTestVectors[1];
  SslHashXof hash(HashAlgorithm::SHAKE256);
  hash.Update(test.input);

  // Verify NIST test vector
  auto result256 = hash.CumulativeHash(kOutputLength256);
  EXPECT_EQ(absl::BytesToHexString(absl::string_view(
                (const char*)result256.data(), result256.size())),
            test.output_256);

  // Test variable length outputs
  auto result128 = hash.CumulativeHash(kOutputLength128);
  auto result1024 = hash.CumulativeHash(kOutputLength1024);

  // Verify sizes
  EXPECT_EQ(result128.size(), kOutputLength128);
  EXPECT_EQ(result256.size(), kOutputLength256);
  EXPECT_EQ(result1024.size(), kOutputLength1024);

  // Verify prefix property
  EXPECT_EQ(std::vector<uint8_t>(result256.begin(),
                                 result256.begin() + kOutputLength128),
            result128);
  EXPECT_EQ(std::vector<uint8_t>(result1024.begin(),
                                 result1024.begin() + kOutputLength256),
            result256);
}

TEST(XofHashTest, TestIncrementalUpdate) {
  const std::string input1 = "Hello, ";
  const std::string input2 = "World!";

  SslHashXof hash1(HashAlgorithm::SHAKE256);
  hash1.Update(input1 + input2);
  auto result1 = hash1.CumulativeHash(kOutputLength256);

  SslHashXof hash2(HashAlgorithm::SHAKE256);
  hash2.Update(input1).Update(input2);
  auto result2 = hash2.CumulativeHash(kOutputLength256);

  EXPECT_EQ(result1, result2);
}

TEST(XofHashTest, TestReset) {
  const auto& test = kTestVectors[1];

  SslHashXof hash(HashAlgorithm::SHAKE256);
  hash.Update(test.input);
  auto result1 = hash.CumulativeHash(kOutputLength256);

  hash.Reset().Update(test.input);
  auto result2 = hash.CumulativeHash(kOutputLength256);

  EXPECT_EQ(result1, result2);
  EXPECT_EQ(absl::BytesToHexString(
                absl::string_view((const char*)result1.data(), result1.size())),
            test.output_256);
}

}  // namespace yacl::crypto
