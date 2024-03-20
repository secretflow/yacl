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

#include "absl/types/span.h"

namespace yacl::crypto {

void SmEnvSeal(ByteContainerView pub_key, ByteContainerView iv,
               ByteContainerView plaintext, std::vector<uint8_t>* encrypted_key,
               std::vector<uint8_t>* ciphertext) {
  // Step 1. Generate random 16 bytes key for SM4.
  std::vector<uint8_t> symmetric_key = SecureRandBytes(16);

  // Step 2. Do sm4-mac
  *ciphertext = Sm4MteEncrypt(symmetric_key, iv, plaintext);

  // Step 3. Encrypte symmetric key using SM2
  *encrypted_key = Sm2Encryptor(pub_key).Encrypt(symmetric_key);
}

void SmEnvOpen(ByteContainerView pri_key, ByteContainerView iv,
               ByteContainerView encrypted_key, ByteContainerView ciphertext,
               std::vector<uint8_t>* plaintext) {
  std::vector<uint8_t> symmetric_key =
      Sm2Decryptor(pri_key).Decrypt(encrypted_key);
  *plaintext = Sm4MteDecrypt(symmetric_key, iv, ciphertext);
}

void RsaEnvSeal(ByteContainerView pub_key, ByteContainerView iv,
                ByteContainerView plaintext,
                std::vector<uint8_t>* encrypted_key,
                std::vector<uint8_t>* ciphertext, std::vector<uint8_t>* mac) {
  std::vector<uint8_t> symmetric_key = SecureRandBytes(16);
  ciphertext->resize(plaintext.size());
  // Aes-128 mac size is 16 bytes.
  mac->resize(16);
  Aes128GcmCrypto(symmetric_key, iv)
      .Encrypt(plaintext, "", absl::Span<uint8_t>(*ciphertext),
               absl::Span<uint8_t>(*mac));
  *encrypted_key = RsaEncryptor(pub_key).Encrypt(symmetric_key);
}

void RsaEnvOpen(ByteContainerView pri_key, ByteContainerView iv,
                ByteContainerView encrypted_key, ByteContainerView ciphertext,
                ByteContainerView mac, std::vector<uint8_t>* plaintext) {
  std::vector<uint8_t> symmetric_key =
      RsaDecryptor(pri_key).Decrypt(encrypted_key);
  plaintext->resize(ciphertext.size());
  Aes128GcmCrypto(symmetric_key, iv)
      .Decrypt(ciphertext, "", mac, absl::Span<uint8_t>(*plaintext));
}

}  // namespace yacl::crypto
