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

#include <cstring>
#include <memory>

#include "gtest/gtest.h"

#include "yacl/base/exception.h"
#include "yacl/crypto/base/aes/aes_intrinsics.h"

namespace yacl::crypto {

namespace {

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

// clang-format on

}  // namespace

TEST(AesTest, EncExample) {
  uint128_t key_block;
  AES_KEY aes_key;
  memcpy(&key_block, kKeyExample, sizeof(key_block));
  AES_set_encrypt_key(key_block, &aes_key);

  std::vector<uint8_t> cipher_bytes(kPlaintextExample.size());
  std::vector<uint128_t> plain_blocks(kPlaintextExample.size() / 16);
  std::vector<uint128_t> cipher_blocks(kPlaintextExample.size() / 16);
  std::memcpy(plain_blocks.data(), kPlaintextExample.data(),
              kPlaintextExample.size());

  AES_ecb_encrypt_blks(aes_key, absl::MakeConstSpan(plain_blocks),
                       absl::MakeSpan(cipher_blocks));

  std::memcpy(cipher_bytes.data(), cipher_blocks.data(), cipher_bytes.size());
  EXPECT_EQ(cipher_bytes, kCiphertextExample);
}

TEST(AesTest, DecExample) {
  uint128_t key_block;
  AES_KEY aes_key;
  memcpy(&key_block, kKeyExample, sizeof(key_block));
  AES_set_decrypt_key(key_block, &aes_key);

  std::vector<uint8_t> plain_bytes(kPlaintextExample.size());
  std::vector<uint128_t> plain_blocks(kPlaintextExample.size() / 16);
  std::vector<uint128_t> cipher_blocks(kPlaintextExample.size() / 16);

  std::memcpy(cipher_blocks.data(), kCiphertextExample.data(),
              kCiphertextExample.size());

  AES_ecb_decrypt_blks(aes_key, absl::MakeConstSpan(cipher_blocks),
                       absl::MakeSpan(plain_blocks));

  std::memcpy(plain_bytes.data(), plain_blocks.data(), plain_bytes.size());
  EXPECT_EQ(plain_bytes, kPlaintextExample);
}

}  // namespace yacl::crypto
