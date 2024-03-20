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

#include "yacl/crypto/envelope/digital_envelope.h"

#include "gtest/gtest.h"

#include "yacl/crypto/key_utils.h"

namespace yacl::crypto {

TEST(SmDigitalEnvelope, SealOpen_shouldOk) {
  // GIVEN
  auto [pk, sk] = GenSm2KeyPairToPemBuf();
  std::string plaintext = "I am a plaintext.";
  std::string iv = "1234567812345678";

  // WHEN
  std::vector<uint8_t> ciphertext;
  std::vector<uint8_t> encrypted_key;
  SmEnvSeal(pk, iv, plaintext, &encrypted_key, &ciphertext);

  std::vector<uint8_t> decrypted;
  SmEnvOpen(sk, iv, encrypted_key, ciphertext, &decrypted);

  // THEN
  EXPECT_EQ(plaintext, std::string(decrypted.begin(), decrypted.end()));
}

TEST(RsaDigitalEnvelope, SealOpen_shouldOk) {
  // GIVEN
  auto [pk, sk] = GenRsaKeyPairToPemBuf();
  std::string plaintext = "I am a plaintext.";
  std::string iv = "123456781234";

  // WHEN
  std::vector<uint8_t> ciphertext;
  std::vector<uint8_t> encrypted_key;
  std::vector<uint8_t> mac;
  RsaEnvSeal(pk, iv, plaintext, &encrypted_key, &ciphertext, &mac);

  std::vector<uint8_t> decrypted;
  RsaEnvOpen(sk, iv, encrypted_key, ciphertext, mac, &decrypted);

  // THEN
  EXPECT_EQ(plaintext, std::string(decrypted.begin(), decrypted.end()));
}

}  // namespace yacl::crypto
