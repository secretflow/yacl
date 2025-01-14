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

#include "yacl/crypto/aead/aead.h"

#include <string>

#include "gtest/gtest.h"

#include "yacl/crypto/aead/sm4_mte.h"
#include "yacl/crypto/rand/rand.h"

namespace yacl::crypto {

constexpr char iv_96[] = "000000000000";

class AeadAlgorithmsTest : public testing::TestWithParam<AeadAlgorithm> {};

// This will create multiple tests.
TEST_P(AeadAlgorithmsTest, EncryptDecrypt_ShouldOk) {
  AeadAlgorithm algorithm = GetParam();
  auto key = FastRandBytes(AeadCtx::GetKeySize(algorithm));
  auto iv = ByteContainerView(iv_96, sizeof(iv_96) - 1);

  auto aead_cxt = AeadCtx(algorithm);
  std::string plaintext = "I am a plaintext.";
  std::string aad = "This is additional authenticated data.";
  size_t additional_cipher_size =
      algorithm == AeadAlgorithm::SM4_MTE_HMAC_SM3 ? kSm4MteMacCipherSize : 0;
  std::vector<uint8_t> ciphertext(plaintext.size() + additional_cipher_size);
  std::vector<uint8_t> mac(aead_cxt.GetMacSize());

  aead_cxt.Encrypt(plaintext, key, iv, absl::MakeSpan(ciphertext),
                   absl::MakeSpan(mac), aad);

  std::vector<uint8_t> decrypted(plaintext.size());

  aead_cxt.Decrypt(ciphertext, mac, key, iv, absl::MakeSpan(decrypted), aad);

  EXPECT_EQ(plaintext, std::string(decrypted.begin(), decrypted.end()));
}

TEST_P(AeadAlgorithmsTest, EncryptDecrypt_withErrorGMAC_ShouldThrowException) {
  AeadAlgorithm algorithm = GetParam();
  auto key = FastRandBytes(AeadCtx::GetKeySize(algorithm));
  auto iv = ByteContainerView(iv_96, sizeof(iv_96) - 1);

  auto aead_cxt = AeadCtx(algorithm);
  std::string plaintext = "I am a plaintext.";
  std::string aad = "This is additional authenticated data.";
  size_t additional_cipher_size =
      algorithm == AeadAlgorithm::SM4_MTE_HMAC_SM3 ? kSm4MteMacCipherSize : 0;
  std::vector<uint8_t> ciphertext(plaintext.size() + additional_cipher_size);
  std::vector<uint8_t> mac(aead_cxt.GetMacSize());

  aead_cxt.Encrypt(plaintext, key, iv, absl::MakeSpan(ciphertext),
                   absl::MakeSpan(mac), aad);

  std::vector<uint8_t> decrypted(plaintext.size());

  if (algorithm == AeadAlgorithm::SM4_MTE_HMAC_SM3) {
    // wrong cipher, SM4_MTE_HMAC_SM3 does not have plaintext mac
    ciphertext[0] += 1;
  } else {
    // wrong mac
    mac[0] += 1;
  }

  // THEN
  EXPECT_ANY_THROW({
    aead_cxt.Decrypt(ciphertext, mac, key, iv, absl::MakeSpan(decrypted), aad);
  });
}

INSTANTIATE_TEST_SUITE_P(AeadTest, AeadAlgorithmsTest,
                         testing::Values(AeadAlgorithm::AES128_GCM,
                                         AeadAlgorithm::AES256_GCM,
#ifdef YACL_WITH_TONGSUO
                                         AeadAlgorithm::SM4_GCM,
#endif
                                         AeadAlgorithm::SM4_MTE_HMAC_SM3));

}  // namespace yacl::crypto
