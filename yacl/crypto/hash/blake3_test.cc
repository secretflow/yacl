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

#include "yacl/crypto/hash/blake3.h"

#include <limits>
#include <string>
#include <vector>

#include "absl/strings/escaping.h"
#include "gtest/gtest.h"

#include "yacl/base/exception.h"

namespace yacl::crypto {
struct TestData {
  // Hash data
  std::string vector1;
  // Hash result
  std::string result1;
  // Hash data
  std::string vector2;
  // Hash result
  std::string result2;
  // vector2 without vector1 prefix.
  std::string suffix;
};

//
// blake3 test vector from
// https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json
// two case: len: 3 and 65
//
TestData test_data_blake3 = {
    "000102",
    "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f",
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324"
    "25262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40",
    "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee",
    "030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627"
    "28292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"};

TEST(Blake3HashTest, TestVector1) {
  Blake3Hash blake3;
  std::string vector_bytes = absl::HexStringToBytes(test_data_blake3.vector1);

  std::vector<uint8_t> hash = blake3.Update(vector_bytes).CumulativeHash();

  EXPECT_EQ(absl::BytesToHexString(
                absl::string_view((const char*)hash.data(), hash.size())),
            test_data_blake3.result1);
}

TEST(Blake3HashTest, TestVector2) {
  Blake3Hash blake3;
  std::string vector_bytes = absl::HexStringToBytes(test_data_blake3.vector2);

  std::vector<uint8_t> hash = blake3.Update(vector_bytes).CumulativeHash();

  EXPECT_EQ(absl::BytesToHexString(
                absl::string_view((const char*)hash.data(), hash.size())),
            test_data_blake3.result2);
}

// Verify that calling Reset() after addition of some data resets the object to
// a clean state, allowing a new hash operation to take place.
TEST(Blake3HashTest, ResetBetweenUpdates) {
  Blake3Hash blake3;
  std::string vector1_bytes = absl::HexStringToBytes(test_data_blake3.vector1);
  std::string vector2_bytes = absl::HexStringToBytes(test_data_blake3.vector2);
  std::vector<uint8_t> hash = blake3.Update(vector1_bytes)
                                  .Reset()
                                  .Update(vector2_bytes)
                                  .CumulativeHash();
  EXPECT_EQ(absl::BytesToHexString(
                absl::string_view((const char*)hash.data(), hash.size())),
            test_data_blake3.result2);
}

// Verify that the correct hash is computed when the input is added over several
// calls to Update.
TEST(Blake3HashTest, MultipleUpdates) {
  Blake3Hash blake3;
  std::string vector1_bytes = absl::HexStringToBytes(test_data_blake3.vector1);
  std::string suffix_bytes = absl::HexStringToBytes(test_data_blake3.suffix);

  std::vector<uint8_t> result = blake3.Update(vector1_bytes).CumulativeHash();
  EXPECT_EQ(absl::BytesToHexString(
                absl::string_view((const char*)result.data(), result.size())),
            test_data_blake3.result1);

  result = blake3.Update(suffix_bytes).CumulativeHash();
  EXPECT_EQ(absl::BytesToHexString(
                absl::string_view((const char*)result.data(), result.size())),
            test_data_blake3.result2);
}

// Verify that blacke3 could extract different output length as needed.
// The blow testing would set the output length from 1 byte (8-bit) to 8 * 32 =
// 256 bytes (2048-bit).
// Besdies, the output length would affect the security level, see
// yacl/crypto/hash/blake3.h for more details.
TEST(Blake3HashTest, CustomOutLength) {
  for (size_t i = 0; i <= (8 * BLAKE3_OUT_LEN); i++) {
    Blake3Hash blake3(i);

    std::string vector1_bytes =
        absl::HexStringToBytes(test_data_blake3.vector1);

    // Shorter outputs are prefixes of longer ones.
    // reference
    // https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf
    // Section 2.6
    std::vector<uint8_t> result = blake3.Update(vector1_bytes).CumulativeHash();
    auto cur_result = absl::BytesToHexString(
        absl::string_view((const char*)result.data(), result.size()));

    // find minimum length
    auto len = std::min(i, static_cast<size_t>(BLAKE3_OUT_LEN));
    EXPECT_EQ(cur_result.substr(0, 2 * len),
              test_data_blake3.result1.substr(0, 2 * len));
  }
}

//
// Blake3 support arbitrary output length
// reference:
// 1. https://en.wikipedia.org/wiki/List_of_hash_functions
// 2. https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf
// Section 2.6
//
TEST(Blake3HashTest, MaximumLength) {
  size_t max_size = 1 << 25;  // 2^25 bytes, 2^28-bit

  Blake3Hash blake3(max_size);

  std::string vector1_bytes = absl::HexStringToBytes(test_data_blake3.vector1);

  auto len = std::min(max_size, static_cast<size_t>(BLAKE3_OUT_LEN));

  std::string std_result = test_data_blake3.result1.substr(0, 2 * len);
  std::vector<uint8_t> result = blake3.Update(vector1_bytes).CumulativeHash();
  auto cur_result = absl::BytesToHexString(
      absl::string_view((const char*)result.data(), result.size()));

  EXPECT_EQ(cur_result.substr(0, 2 * len), std_result);
}

}  // namespace yacl::crypto
