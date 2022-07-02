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

#pragma once

#include <memory>

#include "openssl/bio.h"
#include "openssl/evp.h"
#include "openssl/rsa.h"
#include "openssl/x509.h"

#include "yasl/base/byte_container_view.h"
#include "yasl/crypto/asymmetric_crypto.h"

namespace yasl::crypto {

class RsaEncryptor : public crypto::AsymmetricEncryptor {
 public:
  using UniqueRsa = std::unique_ptr<RSA, decltype(&RSA_free)>;
  using UniqueBio = std::unique_ptr<BIO, decltype(&BIO_free)>;
  using UniqueX509 = std::unique_ptr<X509, decltype(&X509_free)>;
  using UniqueEVP = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

  static std::unique_ptr<RsaEncryptor> CreateFromX509(
      ByteContainerView x509_public_key);
  static std::unique_ptr<RsaEncryptor> CreateFromPem(
      ByteContainerView public_key);

  AsymCryptoSchema GetSchema() const override;

  std::vector<uint8_t> Encrypt(ByteContainerView plaintext) override;

 private:
  explicit RsaEncryptor(UniqueRsa rsa)
      : rsa_(std::move(rsa)), schema_(AsymCryptoSchema::RSA2048_OAEP) {}

  const UniqueRsa rsa_;
  const AsymCryptoSchema schema_;
};

class RsaDecryptor : public crypto::AsymmetricDecryptor {
 public:
  using UniqueRsa = std::unique_ptr<RSA, decltype(&RSA_free)>;
  using UniqueBio = std::unique_ptr<BIO, decltype(&BIO_free)>;
  using UniqueX509 = std::unique_ptr<X509, decltype(&X509_free)>;

  static std::unique_ptr<RsaDecryptor> CreateFromPem(
      ByteContainerView private_key);

  AsymCryptoSchema GetSchema() const override;

  std::vector<uint8_t> Decrypt(ByteContainerView ciphertext) override;

 private:
  explicit RsaDecryptor(UniqueRsa rsa)
      : rsa_(std::move(rsa)), schema_(AsymCryptoSchema::RSA2048_OAEP) {}

  const UniqueRsa rsa_;
  const AsymCryptoSchema schema_;
};

}  // namespace yasl::crypto