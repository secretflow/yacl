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

#include "absl/strings/escaping.h"
#include "gtest/gtest.h"

#include "yacl/base/exception.h"
#include "yacl/crypto/hash/ssl_hash.h"

namespace yacl::crypto {

template <typename T>
class SslHashTest : public testing::Test {
 public:
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

  void SetUp() override {
    // The following two test vectors are taken from
    // https://www.oscca.gov.cn/sca/xxgk/2010-12/17/1002389/files/302a3ada057c4a73830536d03e683110.pdf
    test_data_sm3_ = {
        "abc",
        "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
        "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
        "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
        "dabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"};
    // The following two test vectors are taken from
    // http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA256.pdf.
    test_data_sha256_ = {
        "abc",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        "dbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"};
    // The following two test vectors are taken from
    // https://tools.ietf.org/html/rfc7693
    test_data_blake2b_ = {
        "abc",
        "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5"
        "392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
        "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
        "9d6dac6d7d8fc6bf1d389d7d1f8e1f8a17c69e5ee3120871c10a4322849e5cef1e6db5"
        "f5e968ee7c39d9d76e74806dd7e34a7d58e8c901883787c8edf7809072",
        "dabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"};
  }

 protected:
  const TestData& Data() {
    if (std::is_same<T, Sm3Hash>::value) {
      return test_data_sm3_;
    } else if (std::is_same<T, Sha256Hash>::value) {
      return test_data_sha256_;
    } else if (std::is_same<T, Blake2Hash>::value) {
      return test_data_blake2b_;
    }

    YACL_THROW("Unsupported type name!");
  }

  TestData test_data_sm3_;
  TestData test_data_sha256_;
  TestData test_data_blake2b_;
};

using MyTypes = ::testing::Types<Sm3Hash, Sha256Hash, Blake2Hash>;
TYPED_TEST_SUITE(SslHashTest, MyTypes);

TYPED_TEST(SslHashTest, TestVector1) {
  std::vector<uint8_t> hash =
      TypeParam().Update(this->Data().vector1).CumulativeHash();
  EXPECT_EQ(absl::BytesToHexString(
                absl::string_view((const char*)hash.data(), hash.size())),
            this->Data().result1);
}

TYPED_TEST(SslHashTest, TestVector2) {
  std::vector<uint8_t> hash =
      TypeParam().Update(this->Data().vector2).CumulativeHash();
  EXPECT_EQ(absl::BytesToHexString(
                absl::string_view((const char*)hash.data(), hash.size())),
            this->Data().result2);
}

// Verify that calling Reset() after addition of some data resets the object to
// a clean state, allowing a new hash operation to take place.
TYPED_TEST(SslHashTest, ResetBetweenUpdates) {
  std::vector<uint8_t> hash = TypeParam()
                                  .Update(this->Data().vector1)
                                  .Reset()
                                  .Update(this->Data().vector2)
                                  .CumulativeHash();
  EXPECT_EQ(absl::BytesToHexString(
                absl::string_view((const char*)hash.data(), hash.size())),
            this->Data().result2);
}

// Verify that the correct hash is computed when the input is added over several
// calls to Update.
TYPED_TEST(SslHashTest, MultipleUpdates) {
  TypeParam hash;
  std::vector<uint8_t> result =
      hash.Update(this->Data().vector1).CumulativeHash();
  EXPECT_EQ(absl::BytesToHexString(
                absl::string_view((const char*)result.data(), result.size())),
            this->Data().result1);

  result = hash.Update(this->Data().suffix).CumulativeHash();
  EXPECT_EQ(absl::BytesToHexString(
                absl::string_view((const char*)result.data(), result.size())),
            this->Data().result2);
}

}  // namespace yacl::crypto
