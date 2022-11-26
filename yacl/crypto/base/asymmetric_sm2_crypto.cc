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

#include "yacl/crypto/base/asymmetric_sm2_crypto.h"

#include <iostream>

#include "absl/memory/memory.h"
#include "openssl/pem.h"

#include "yacl/base/exception.h"
#include "yacl/crypto/base/asymmetric_util.h"
#include "yacl/utils/scope_guard.h"

namespace yacl::crypto {

std::unique_ptr<Sm2Encryptor> Sm2Encryptor::CreateFromPem(
    ByteContainerView sm2_pem) {
  // Using `new` to access a non-public constructor.
  // ref https://abseil.io/tips/134
  return absl::WrapUnique<Sm2Encryptor>(
      new Sm2Encryptor(internal::CreatePubPkeyFromSm2Pem(sm2_pem)));
}

AsymCryptoSchema Sm2Encryptor::GetSchema() const { return schema_; }

std::vector<uint8_t> Sm2Encryptor::Encrypt(ByteContainerView plaintext) {
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey_.get(), nullptr);
  YACL_ENFORCE(ctx != nullptr, "Failed to create EVP_PKEY_CTX");
  YACL_ENFORCE_GT(EVP_PKEY_encrypt_init(ctx), 0);
  ON_SCOPE_EXIT([&] { EVP_PKEY_CTX_free(ctx); });
  size_t cipher_len;
  // Determine buffer length.
  // Note that cipher_len is the maximum but not exact size of the output
  // buffer. Ref
  // https://www.openssl.org/docs/man1.1.1/man3/EVP_PKEY_encrypt.html
  YACL_ENFORCE_GT(EVP_PKEY_encrypt(ctx, nullptr, &cipher_len, plaintext.data(),
                                   plaintext.size()),
                  0);
  std::vector<uint8_t> ciphertext(cipher_len);
  // Do encryption
  YACL_ENFORCE_GT(EVP_PKEY_encrypt(ctx, ciphertext.data(), &cipher_len,
                                   plaintext.data(), plaintext.size()),
                  0);
  // Correct the size to actual size.
  ciphertext.resize(cipher_len);
  return ciphertext;
}

std::unique_ptr<Sm2Decryptor> Sm2Decryptor::CreateFromPem(
    ByteContainerView sm2_pem) {
  return absl::WrapUnique<Sm2Decryptor>(
      new Sm2Decryptor(internal::CreatePriPkeyFromSm2Pem(sm2_pem)));
}

AsymCryptoSchema Sm2Decryptor::GetSchema() const { return schema_; }

std::vector<uint8_t> Sm2Decryptor::Decrypt(ByteContainerView ciphertext) {
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey_.get(), nullptr);
  YACL_ENFORCE(ctx != nullptr);
  ON_SCOPE_EXIT([&] { EVP_PKEY_CTX_free(ctx); });
  YACL_ENFORCE_GT(EVP_PKEY_decrypt_init(ctx), 0);

  size_t plain_len;
  // Determine buffer length.
  // Note that plain_len is the maximum but not exact size of the output
  // buffer. Ref
  // https://www.openssl.org/docs/man1.1.1/man3/EVP_PKEY_decrypt.html
  YACL_ENFORCE_GT(EVP_PKEY_decrypt(ctx, nullptr, &plain_len, ciphertext.data(),
                                   ciphertext.size()),
                  0);
  std::vector<uint8_t> plaintext(plain_len);
  // Do encryption
  YACL_ENFORCE_GT(EVP_PKEY_decrypt(ctx, plaintext.data(), &plain_len,
                                   ciphertext.data(), ciphertext.size()),
                  0);
  // Correct the size to actual size.
  plaintext.resize(plain_len);
  return plaintext;
}

}  // namespace yacl::crypto