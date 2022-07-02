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

#include "yasl/crypto/asymmetric_rsa_crypto.h"

#include <iostream>

#include "absl/memory/memory.h"
#include "openssl/pem.h"

#include "yasl/base/exception.h"
#include "yasl/crypto/asymmetric_util.h"

namespace yasl::crypto {

namespace {

constexpr int kRsaInputSizeLimitOffset = 41;
constexpr int kRsaPadding = RSA_PKCS1_OAEP_PADDING;

}  // namespace

std::unique_ptr<RsaEncryptor> RsaEncryptor::CreateFromX509(
    ByteContainerView x509_public_key) {
  UniqueBio pem_bio(
      BIO_new_mem_buf(x509_public_key.data(), x509_public_key.size()),
      BIO_free);
  X509* cert = PEM_read_bio_X509(pem_bio.get(), nullptr, nullptr, nullptr);
  YASL_ENFORCE(cert, "No X509 from cert.");
  UniqueX509 unique_cert(cert, ::X509_free);
  EVP_PKEY* pubkey = X509_get_pubkey(unique_cert.get());
  YASL_ENFORCE(pubkey, "No pubkey in x509.");
  UniqueEVP unique_pkey(pubkey, ::EVP_PKEY_free);
  RSA* rsa = EVP_PKEY_get1_RSA(unique_pkey.get());
  YASL_ENFORCE(rsa, "No Rsa from pem string.");
  // Using `new` to access a non-public constructor.
  // ref https://abseil.io/tips/134
  return std::unique_ptr<RsaEncryptor>(
      new RsaEncryptor(UniqueRsa(rsa, ::RSA_free)));
}

std::unique_ptr<RsaEncryptor> RsaEncryptor::CreateFromPem(
    ByteContainerView public_key) {
  UniqueBio pem_bio(BIO_new_mem_buf(public_key.data(), public_key.size()),
                    BIO_free);
  RSA* rsa =
      PEM_read_bio_RSAPublicKey(pem_bio.get(), nullptr, nullptr, nullptr);
  YASL_ENFORCE(rsa, "No rsa from pem.");
  return std::unique_ptr<RsaEncryptor>(
      new RsaEncryptor(UniqueRsa(rsa, ::RSA_free)));
}

AsymCryptoSchema RsaEncryptor::GetSchema() const { return schema_; }

std::vector<uint8_t> RsaEncryptor::Encrypt(ByteContainerView plaintext) {
  int buf_size = RSA_size(rsa_.get());
  YASL_ENFORCE_GT(buf_size, 0, "Illegal RSA_size.");
  YASL_ENFORCE_LT((int)plaintext.size() + kRsaInputSizeLimitOffset, buf_size,
                  "Invalid input size.");
  std::vector<uint8_t> ciphertext(buf_size);
  int rc = RSA_public_encrypt(plaintext.size(), plaintext.data(),
                              ciphertext.data(), rsa_.get(), kRsaPadding);
  YASL_ENFORCE_GT(rc, 0, "Rsa encrypt error.");
  ciphertext.resize(rc);
  return ciphertext;
}

std::unique_ptr<RsaDecryptor> RsaDecryptor::CreateFromPem(
    ByteContainerView private_key) {
  UniqueBio pem_bio(BIO_new_mem_buf(private_key.data(), private_key.size()),
                    BIO_free);
  RSA* rsa =
      PEM_read_bio_RSAPrivateKey(pem_bio.get(), nullptr, nullptr, nullptr);
  YASL_ENFORCE(rsa, "No rsa from string.");
  return std::unique_ptr<RsaDecryptor>(
      new RsaDecryptor(UniqueRsa(rsa, ::RSA_free)));
}

AsymCryptoSchema RsaDecryptor::GetSchema() const { return schema_; }

std::vector<uint8_t> RsaDecryptor::Decrypt(ByteContainerView ciphertext) {
  int buf_size = RSA_size(rsa_.get());
  YASL_ENFORCE_GT(buf_size, 0, "Illegal RSA_size.");
  std::vector<uint8_t> plaintext(buf_size);
  int rc = RSA_private_decrypt(ciphertext.size(), ciphertext.data(),
                               plaintext.data(), rsa_.get(), kRsaPadding);
  YASL_ENFORCE_GE(rc, 0, "Rsa decrypt error.");
  plaintext.resize(rc);
  return plaintext;
}

}  // namespace yasl::crypto