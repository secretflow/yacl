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

#include "yacl/crypto/pke/asymmetric_rsa_crypto.h"

#include <vector>

#include "yacl/base/exception.h"

namespace yacl::crypto {

namespace {
// see: https://www.openssl.org/docs/man3.0/man3/RSA_public_encrypt.html
// RSA_PKCS1_OAEP_PADDING: EME-OAEP as defined in PKCS #1 v2.0 with SHA-1, MGF1
// and an empty encoding parameter. This mode is recommended for all new
// applications.
constexpr int kRsaPadding = RSA_PKCS1_OAEP_PADDING;
}  // namespace

std::vector<uint8_t> RsaEncryptor::Encrypt(ByteContainerView plaintext) {
  // see: https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_encrypt.html
  auto ctx = openssl::UniquePkeyCtx(
      EVP_PKEY_CTX_new(pk_.get(), /* engine = default */ nullptr));
  YACL_ENFORCE(ctx != nullptr);

  // init context
  OSSL_RET_1(EVP_PKEY_encrypt_init(ctx.get()));

  // make sure to use OAEP_PADDING
  OSSL_RET_1(EVP_PKEY_CTX_set_rsa_padding(ctx.get(), kRsaPadding));

  // first, get output length
  size_t outlen = 0;
  OSSL_RET_1(EVP_PKEY_encrypt(ctx.get(), /* empty input */ nullptr, &outlen,
                              plaintext.data(), plaintext.size()));

  // then encrypt
  std::vector<uint8_t> out(outlen);
  OSSL_RET_1(EVP_PKEY_encrypt(ctx.get(), out.data(), &outlen, plaintext.data(),
                              plaintext.size()));

  out.resize(outlen); /* important */
  return out;
}

std::vector<uint8_t> RsaDecryptor::Decrypt(ByteContainerView ciphertext) {
  // see: https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_encrypt.html
  auto ctx = openssl::UniquePkeyCtx(
      EVP_PKEY_CTX_new(sk_.get(), /* engine = default */ nullptr));
  YACL_ENFORCE(ctx != nullptr);

  // init context
  OSSL_RET_1(EVP_PKEY_decrypt_init(ctx.get()));

  // make sure to use OAEP_PADDING
  OSSL_RET_1(EVP_PKEY_CTX_set_rsa_padding(ctx.get(), kRsaPadding));

  // first, get output length
  size_t outlen = 0;
  OSSL_RET_1(EVP_PKEY_decrypt(ctx.get(), /* empty input */ nullptr, &outlen,
                              ciphertext.data(), ciphertext.size()));

  // then decrypt
  std::vector<uint8_t> out(outlen);
  OSSL_RET_1(EVP_PKEY_decrypt(ctx.get(), out.data(), &outlen, ciphertext.data(),
                              ciphertext.size()));

  out.resize(outlen); /* important */
  return out;
}

}  // namespace yacl::crypto
