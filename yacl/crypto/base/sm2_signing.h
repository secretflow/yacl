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
#include "openssl/x509.h"

#include "yacl/crypto/base/signing.h"

namespace yacl::crypto {

// The length of default sm2 id.
inline constexpr size_t SM2_ID_DEFAULT_LENGTH = 16;
// The default sm2 id.
// Ref the last chapter of
// http://www.gmbz.org.cn/main/viewfile/2018011001400692565.html
inline constexpr char SM2_ID_DEFAULT[SM2_ID_DEFAULT_LENGTH + 1] =
    "1234567812345678";

class Sm2Signer final : public crypto::AsymmetricSigner {
 public:
  using UniquePkey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

  static std::unique_ptr<Sm2Signer> CreateFromPem(ByteContainerView sm2_pem);

  SignatureScheme GetSignatureSchema() const override;

  // Sign message with the default id.
  std::vector<uint8_t> Sign(ByteContainerView message) const override;
  // Sign message with the specific id.
  std::vector<uint8_t> Sign(ByteContainerView message,
                            ByteContainerView id) const;

 private:
  explicit Sm2Signer(UniquePkey pkey)
      : pkey_(std::move(pkey)),
        schema_(SignatureScheme::SM2_SIGNING_SM3_HASH) {}

  const UniquePkey pkey_;
  const SignatureScheme schema_;
};

class Sm2Verifier final : public crypto::AsymmetricVerifier {
 public:
  using UniquePkey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
  using UniqueBio = std::unique_ptr<BIO, decltype(&BIO_free)>;
  using UniqueX509 = std::unique_ptr<X509, decltype(&X509_free)>;

  static std::unique_ptr<Sm2Verifier> CreateFromPem(ByteContainerView sm2_pem);
  static std::unique_ptr<Sm2Verifier> CreateFromOct(ByteContainerView sm2_oct);
  static std::unique_ptr<Sm2Verifier> CreateFromCertPem(
      ByteContainerView sm2_cert_pem);
  static std::unique_ptr<Sm2Verifier> CreateFromCertDer(
      ByteContainerView sm2_cert_der);

  SignatureScheme GetSignatureSchema() const override;

  // Verify signature with the default id.
  void Verify(ByteContainerView message,
              ByteContainerView signature) const override;

  // Verify signature with the specific id.
  void Verify(ByteContainerView message, ByteContainerView signature,
              ByteContainerView id) const;

 private:
  explicit Sm2Verifier(UniquePkey pkey)
      : pkey_(std::move(pkey)),
        schema_(SignatureScheme::SM2_SIGNING_SM3_HASH) {}

  const UniquePkey pkey_;
  const SignatureScheme schema_;
};

// TODO @raofei: support sm2 certificate

}  // namespace yacl::crypto