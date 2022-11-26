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

#include "yacl/crypto/base/asymmetric_rsa_crypto.h"

#include "gtest/gtest.h"

#include "yacl/crypto/base/asymmetric_util.h"

namespace yacl::crypto {

TEST(AsymmetricRsa, EncryptDecrypt_shouldOk) {
  // GIVEN
  auto [public_key, private_key] = CreateRsaKeyPair();
  std::string plaintext = "I am a plaintext.";

  // WHEN
  auto encryptor = RsaEncryptor::CreateFromPem(public_key);
  auto encrypted = encryptor->Encrypt(plaintext);

  auto decryptor = RsaDecryptor::CreateFromPem(private_key);
  auto decrypted_bytes = decryptor->Decrypt(encrypted);
  std::string decrypted(decrypted_bytes.begin(), decrypted_bytes.end());

  // THEN
  EXPECT_EQ(plaintext, decrypted);
}

}  // namespace yacl::crypto