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

#include "yacl/crypto/aead/gcm_crypto.h"

#include "yacl/crypto/openssl_wrappers.h"

namespace yacl::crypto {

namespace {

constexpr size_t kAesMacSize = 16;

size_t GetMacSize(GcmCryptoSchema schema) {
  switch (schema) {
    case GcmCryptoSchema::AES128_GCM:
    case GcmCryptoSchema::AES256_GCM:
      return kAesMacSize;
    // case GcmCryptoSchema::SM4_GCM:
    //   return kAesMacSize;
    default:
      YACL_THROW("Unknown crypto schema: {}", static_cast<int>(schema));
  }
}

}  // namespace

void GcmCrypto::Encrypt(ByteContainerView plaintext, ByteContainerView aad,
                        absl::Span<uint8_t> ciphertext,
                        absl::Span<uint8_t> mac) const {
  YACL_ENFORCE_EQ(ciphertext.size(), plaintext.size());
  YACL_ENFORCE_EQ(mac.size(), GetMacSize(schema_));

  // init openssl evp cipher context
  auto ctx = openssl::UniqueCipherCtx(EVP_CIPHER_CTX_new());
  YACL_ENFORCE(ctx != nullptr, "Failed to new evp cipher context.");
  const auto cipher = openssl::FetchEvpCipher(ToString(schema_));
  YACL_ENFORCE(cipher != nullptr);
  YACL_ENFORCE(key_.size() == (size_t)EVP_CIPHER_key_length(cipher.get()));
  YACL_ENFORCE(iv_.size() == (size_t)EVP_CIPHER_iv_length(cipher.get()));

  OSSL_RET_1(EVP_EncryptInit_ex(ctx.get(), cipher.get(), nullptr, key_.data(),
                                iv_.data()));

  // Provide AAD data if exist
  int out_length = 0;
  const auto aad_len = aad.size();
  if (aad_len > 0) {
    OSSL_RET_1(EVP_EncryptUpdate(ctx.get(), nullptr, &out_length, aad.data(),
                                 aad_len));
    YACL_ENFORCE(out_length == (int)aad.size());
  }
  OSSL_RET_1(EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &out_length,
                               plaintext.data(), plaintext.size()));
  YACL_ENFORCE(out_length == (int)plaintext.size(),
               "Unexpected encrypte out length.");

  // Note that get no output here as the data is always aligned for GCM.
  EVP_EncryptFinal_ex(ctx.get(), nullptr, &out_length);
  OSSL_RET_1(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG,
                                 GetMacSize(schema_), mac.data()));
}

void GcmCrypto::Decrypt(ByteContainerView ciphertext, ByteContainerView aad,
                        ByteContainerView mac,
                        absl::Span<uint8_t> plaintext) const {
  YACL_ENFORCE_EQ(ciphertext.size(), plaintext.size());
  YACL_ENFORCE_EQ(mac.size(), GetMacSize(schema_));

  // init openssl evp cipher context
  auto ctx = openssl::UniqueCipherCtx(EVP_CIPHER_CTX_new());

  YACL_ENFORCE(ctx.get(), "Failed to new evp cipher context.");

  const auto cipher = openssl::FetchEvpCipher(ToString(schema_));
  YACL_ENFORCE_EQ(key_.size(), (size_t)EVP_CIPHER_key_length(cipher.get()));
  YACL_ENFORCE_EQ(iv_.size(), (size_t)EVP_CIPHER_iv_length(cipher.get()));
  YACL_ENFORCE(EVP_DecryptInit_ex(ctx.get(), cipher.get(), nullptr, key_.data(),
                                  iv_.data()));

  // Provide AAD data if exist
  int out_length = 0;
  const auto aad_len = aad.size();
  if (aad_len > 0) {
    OSSL_RET_1(EVP_DecryptUpdate(ctx.get(), nullptr, &out_length, aad.data(),
                                 aad_len));
    YACL_ENFORCE(out_length == (int)aad.size());
  }
  OSSL_RET_1(EVP_DecryptUpdate(ctx.get(), plaintext.data(), &out_length,
                               ciphertext.data(), ciphertext.size()));
  YACL_ENFORCE(out_length == (int)plaintext.size(),
               "Unexpcted decryption out length.");
  OSSL_RET_1(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG,
                                 GetMacSize(schema_), (void*)mac.data()));

  // Note that get no output here as the data is always aligned for GCM.
  YACL_ENFORCE(EVP_DecryptFinal_ex(ctx.get(), nullptr, &out_length) > 0,
               "Failed to verfiy mac.");
}

}  // namespace yacl::crypto
