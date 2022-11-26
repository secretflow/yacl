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

#include "openssl/bio.h"
#include "openssl/evp.h"
#include "openssl/x509.h"

#include "yacl/crypto/base/signing.h"

namespace yacl::crypto {

// RSA sign with sha256
class RsaSigner final : public crypto::AsymmetricSigner {
 public:
  using UniquePkey = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;

  static std::unique_ptr<RsaSigner> CreateFromPem(ByteContainerView pem);

  SignatureScheme GetSignatureSchema() const override;

  std::vector<uint8_t> Sign(ByteContainerView message) const override;

 private:
  explicit RsaSigner(UniquePkey pkey)
      : pkey_(std::move(pkey)),
        schema_(SignatureScheme::RSA_SIGNING_SHA256_HASH) {}

  const UniquePkey pkey_;
  const SignatureScheme schema_;
};

// RSA verify with sha256
class RsaVerifier final : public crypto::AsymmetricVerifier {
 public:
  using UniquePkey = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
  using UniqueBio = std::unique_ptr<BIO, decltype(&::BIO_free)>;
  using UniqueX509 = std::unique_ptr<X509, decltype(&::X509_free)>;

  static std::unique_ptr<RsaVerifier> CreateFromPem(ByteContainerView pem);

  static std::unique_ptr<RsaVerifier> CreateFromCertPem(
      ByteContainerView cert_pem);

  SignatureScheme GetSignatureSchema() const override;

  void Verify(ByteContainerView message,
              ByteContainerView signature) const override;

 private:
  explicit RsaVerifier(UniquePkey pkey)
      : pkey_(std::move(pkey)),
        schema_(SignatureScheme::RSA_SIGNING_SHA256_HASH) {}

  const UniquePkey pkey_;
  const SignatureScheme schema_;
};

}  // namespace yacl::crypto