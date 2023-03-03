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

#include "yacl/crypto/base/symmetric_crypto.h"

#include <memory>

#include "gtest/gtest.h"

#include "yacl/base/exception.h"
#include "yacl/crypto/base/symmetric_crypto.h"

namespace yacl::crypto {

namespace {

constexpr uint128_t kKey1 = 123;
constexpr uint128_t kKey2 = 456;
constexpr uint128_t kIv1 = 1;
constexpr uint128_t kIv2 = 2;

// clang-format off

// data from nist website
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core128.pdf
constexpr uint8_t kKeyExample[16] = {
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 
    0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
};

std::vector<uint8_t> kPlaintextExample = {
    0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 
    0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A, 
    0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 
    0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51, 
    0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 
    0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF, 
    0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 
    0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10
};

std::vector<uint8_t> kCiphertextExample = {
    0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60, 
    0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66, 0xEF, 0x97, 
    0xF5, 0xD3, 0xD5, 0x85, 0x03, 0xB9, 0x69, 0x9D, 
    0xE7, 0x85, 0x89, 0x5A, 0x96, 0xFD, 0xBA, 0xAF, 
    0x43, 0xB1, 0xCD, 0x7F, 0x59, 0x8E, 0xCE, 0x23, 
    0x88, 0x1B, 0x00, 0xE3, 0xED, 0x03, 0x06, 0x88, 
    0x7B, 0x0C, 0x78, 0x5E, 0x27, 0xE8, 0xAD, 0x3F, 
    0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5D, 0xD4
};

// aes-128 CBC mode standard vector
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CBC.pdf
constexpr uint8_t kIvExample[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};
std::vector<uint8_t> kCbcCiphertextExample = {
    0x76, 0x49, 0xAB, 0xAC, 0x81, 0x19, 0xB2, 0x46, 
    0xCE, 0xE9, 0x8E, 0x9B, 0x12, 0xE9, 0x19, 0x7D, 
    0x50, 0x86, 0xCB, 0x9B, 0x50, 0x72, 0x19, 0xEE, 
    0x95, 0xDB, 0x11, 0x3A, 0x91, 0x76, 0x78, 0xB2, 
    0x73, 0xBE, 0xD6, 0xB8, 0xE3, 0xC1, 0x74, 0x3B, 
    0x71, 0x16, 0xE6, 0x9E, 0x22, 0x22, 0x95, 0x16, 
    0x3F, 0xF1, 0xCA, 0xA1, 0x68, 0x1F, 0xAC, 0x09, 
    0x12, 0x0E, 0xCA, 0x30, 0x75, 0x86, 0xE1, 0xA7
};

/*
 *  aes ctr mode
 *  https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CTR.pdf
 */
constexpr uint8_t kCtrCounter[16] = {
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 
    0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF 
};

std::vector<uint8_t> kCtrCipherExample = {
    0x87, 0x4D, 0x61, 0x91, 0xB6, 0x20, 0xE3, 0x26,
    0x1B, 0xEF, 0x68, 0x64, 0x99, 0x0D, 0xB6, 0xCE,
    0x98, 0x06, 0xF6, 0x6B, 0x79, 0x70, 0xFD, 0xFF, 
    0x86, 0x17, 0x18, 0x7B, 0xB9, 0xFF, 0xFD, 0xFF,
    0x5A, 0xE4, 0xDF, 0x3E, 0xDB, 0xD5, 0xD3, 0x5E,
    0x5B, 0x4F, 0x09, 0x02, 0x0D, 0xB0, 0x3E, 0xAB,
    0x1E, 0x03, 0x1D, 0xDA, 0x2F, 0xBE, 0x03, 0xD1,
    0x79, 0x21, 0x70, 0xA0, 0xF3, 0x00, 0x9C, 0xEE 
};

// clang-format on

std::vector<uint8_t> MakeVector(size_t len) {
  std::vector<uint8_t> ret(len);
  for (size_t i = 0; i < len; ++i) {
    ret[i] = rand() % 256u;
  }
  return ret;
}

std::vector<uint128_t> MakeBlocks(size_t len) {
  std::vector<uint128_t> ret(len);
  for (size_t i = 0; i < len; ++i) {
    ret[i] = rand();
  }
  return ret;
}

const std::vector<SymmetricCrypto::CryptoType> kTestTypes{
    SymmetricCrypto::CryptoType::AES128_ECB,
    SymmetricCrypto::CryptoType::AES128_CBC,
    SymmetricCrypto::CryptoType::AES128_CTR,
    SymmetricCrypto::CryptoType::SM4_ECB,
    SymmetricCrypto::CryptoType::SM4_CBC,
    SymmetricCrypto::CryptoType::SM4_CTR,
};

}  // namespace

class SymmetricCryptoTest : public testing::TestWithParam<size_t> {};

TEST_P(SymmetricCryptoTest, WorksNBlocks) {
  size_t msg_size = GetParam();
  for (auto type : kTestTypes) {
    SymmetricCrypto crypto(type, kKey1, kIv1);
    auto plaintext = MakeVector(msg_size);
    std::vector<uint8_t> encrypted(plaintext.size());
    ASSERT_NO_THROW(crypto.Encrypt(plaintext, absl::MakeSpan(encrypted)));

    std::vector<uint8_t> decrypted(encrypted.size());
    ASSERT_NO_THROW(crypto.Decrypt(absl::MakeConstSpan(encrypted),
                                   absl::MakeSpan(decrypted)));
    EXPECT_EQ(plaintext.size(), decrypted.size());
    EXPECT_EQ(plaintext, decrypted);
  }
}

TEST_P(SymmetricCryptoTest, WorksUint128) {
  size_t msg_size = GetParam();
  for (auto type : kTestTypes) {
    SymmetricCrypto crypto(type, kKey1, kIv1);
    auto plaintext = MakeBlocks(msg_size);
    std::vector<uint128_t> encrypted(plaintext.size());
    ASSERT_NO_THROW(crypto.Encrypt(plaintext, absl::MakeSpan(encrypted)));

    std::vector<uint128_t> decrypted(encrypted.size());
    ASSERT_NO_THROW(crypto.Decrypt(absl::MakeConstSpan(encrypted),
                                   absl::MakeSpan(decrypted)));
    EXPECT_EQ(plaintext.size(), decrypted.size());
    EXPECT_EQ(plaintext, decrypted);
  }
}

INSTANTIATE_TEST_SUITE_P(Cases, SymmetricCryptoTest,
                         testing::Values(0, 16, 32, 128, 1024, 4096));

class SymmetricCryptoPerformanceTest : public testing::TestWithParam<size_t> {};

TEST_P(SymmetricCryptoPerformanceTest, EncryptCountsUint128) {
  size_t loop_count = GetParam();
  for (auto type : kTestTypes) {
    SymmetricCrypto crypto(type, kKey1, kIv1);
    auto plaintext = MakeBlocks(128);

    std::vector<uint128_t> encrypted(plaintext.size());
    for (size_t i = 0; i < loop_count; i++) {
      ASSERT_NO_THROW(crypto.Encrypt(plaintext, absl::MakeSpan(encrypted)));
    }
  }
}

INSTANTIATE_TEST_SUITE_P(Cases, SymmetricCryptoPerformanceTest,
                         testing::Values(100, 1000, 10000));

TEST(SymmetricCrypto, Uint128) {
  for (auto type : kTestTypes) {
    SymmetricCrypto crypto(type, kKey1, kIv1);
    uint128_t input = rand();
    uint128_t encrypted = 0;
    uint128_t decrypted = 0;
    ASSERT_NO_THROW(encrypted = crypto.Encrypt(input));
    ASSERT_NO_THROW(decrypted = crypto.Decrypt(encrypted));
    EXPECT_EQ(decrypted, input);
  }
}

TEST(SymmetricCrypto, WrongKey) {
  for (auto type : kTestTypes) {
    SymmetricCrypto crypto(type, kKey1, kIv1);
    auto plaintext = MakeVector(SymmetricCrypto::BlockSize());
    std::vector<uint8_t> encrypted(plaintext.size());
    ASSERT_NO_THROW(crypto.Encrypt(plaintext, absl::MakeSpan(encrypted)));

    SymmetricCrypto crypto2(type, kKey2, kIv2);
    std::vector<uint8_t> decrypted(encrypted.size());
    ASSERT_NO_THROW(crypto2.Decrypt(absl::MakeConstSpan(encrypted),
                                    absl::MakeSpan(decrypted)));
    EXPECT_NE(decrypted, plaintext);
  }
}

TEST(SymmetricCrypto, PartialBlock) {
  for (auto type : kTestTypes) {
    bool isCTR = ((type == SymmetricCrypto::CryptoType::AES128_CTR) ||
                  (type == SymmetricCrypto::CryptoType::SM4_CTR));
    SymmetricCrypto crypto(type, kKey1, kIv1);
    auto plaintext = MakeVector(SymmetricCrypto::BlockSize() - 1);
    std::vector<uint8_t> encrypted(plaintext.size());
    if (!isCTR) {
      ASSERT_THROW(crypto.Encrypt(plaintext, absl::MakeSpan(encrypted)),
                   Exception);
    } else {
      crypto.Encrypt(plaintext, absl::MakeSpan(encrypted));
    }

    SymmetricCrypto crypto2(type, kKey1, kIv1);
    std::vector<uint8_t> decrypted(encrypted.size());
    if (!isCTR) {
      ASSERT_THROW(crypto2.Decrypt(absl::MakeConstSpan(encrypted),
                                   absl::MakeSpan(decrypted)),
                   Exception);
    } else {
      crypto2.Decrypt(absl::MakeConstSpan(encrypted),
                      absl::MakeSpan(decrypted));
    }
    if (isCTR) {
      // Partial block should work under CRT mode
      EXPECT_EQ(decrypted, plaintext);
    }
  }
}

TEST(SymmetricCrypto, AesEcbExampleKey) {
  // for (auto type : kTestTypes)
  auto type = SymmetricCrypto::CryptoType::AES128_ECB;
  {
    uint128_t aes_key;
    memcpy(&aes_key, kKeyExample, sizeof(aes_key));
    SymmetricCrypto crypto(type, aes_key, kIv1);

    std::vector<uint8_t> encrypted(kPlaintextExample.size());
    ASSERT_NO_THROW(crypto.Encrypt(absl::MakeConstSpan(kPlaintextExample),
                                   absl::MakeSpan(encrypted)));
    EXPECT_EQ(encrypted, kCiphertextExample);

    SymmetricCrypto crypto2(type, aes_key, kIv1);
    std::vector<uint8_t> decrypted(encrypted.size());
    ASSERT_NO_THROW(crypto2.Decrypt(absl::MakeConstSpan(encrypted),
                                    absl::MakeSpan(decrypted)));
    EXPECT_EQ(decrypted, kPlaintextExample);

    // check
    ASSERT_NO_THROW(crypto.Encrypt(absl::MakeConstSpan(kPlaintextExample),
                                   absl::MakeSpan(encrypted)));
    EXPECT_EQ(encrypted, kCiphertextExample);
  }
}

TEST(SymmetricCrypto, AesCbcExampleKey) {
  auto type = SymmetricCrypto::CryptoType::AES128_CBC;
  {
    uint128_t aes_key;
    uint128_t aes_iv;
    memcpy(&aes_key, kKeyExample, sizeof(aes_key));
    memcpy(&aes_iv, kIvExample, sizeof(aes_iv));
    SymmetricCrypto crypto(type, aes_key, aes_iv);

    std::vector<uint8_t> encrypted(kPlaintextExample.size());
    ASSERT_NO_THROW(crypto.Encrypt(absl::MakeConstSpan(kPlaintextExample),
                                   absl::MakeSpan(encrypted)));
    EXPECT_EQ(encrypted, kCbcCiphertextExample);

    SymmetricCrypto crypto2(type, aes_key, aes_iv);
    std::vector<uint8_t> decrypted(encrypted.size());
    ASSERT_NO_THROW(crypto2.Decrypt(absl::MakeConstSpan(encrypted),
                                    absl::MakeSpan(decrypted)));
    EXPECT_EQ(decrypted, kPlaintextExample);

    // check
    ASSERT_NO_THROW(crypto.Encrypt(absl::MakeConstSpan(kPlaintextExample),
                                   absl::MakeSpan(encrypted)));
    EXPECT_EQ(encrypted, kCbcCiphertextExample);
  }
}

TEST(SymmetricCrypto, AesCtrExampleKey) {
  auto type = SymmetricCrypto::CryptoType::AES128_CTR;
  {
    uint128_t aes_key;
    uint128_t aes_counter;
    memcpy(&aes_key, kKeyExample, sizeof(aes_key));
    memcpy(&aes_counter, kCtrCounter, sizeof(aes_counter));
    SymmetricCrypto crypto(type, aes_key, aes_counter);

    std::vector<uint8_t> encrypted(kPlaintextExample.size());
    ASSERT_NO_THROW(crypto.Encrypt(absl::MakeConstSpan(kPlaintextExample),
                                   absl::MakeSpan(encrypted)));
    EXPECT_EQ(encrypted, kCtrCipherExample);

    SymmetricCrypto crypto2(type, aes_key, aes_counter);
    std::vector<uint8_t> decrypted(encrypted.size());
    ASSERT_NO_THROW(crypto2.Decrypt(absl::MakeConstSpan(encrypted),
                                    absl::MakeSpan(decrypted)));
    EXPECT_EQ(decrypted, kPlaintextExample);

    // check
    ASSERT_NO_THROW(crypto.Encrypt(absl::MakeConstSpan(kPlaintextExample),
                                   absl::MakeSpan(encrypted)));
    EXPECT_EQ(encrypted, kCtrCipherExample);
  }
}
}  // namespace yacl::crypto
