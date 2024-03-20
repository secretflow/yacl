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

#include <utility>
#include <vector>

#include "yacl/crypto/key_utils.h"
#include "yacl/crypto/sign/signing.h"
#include "yacl/secparam.h"

/* submodules */
#include "yacl/crypto/hash/hash_utils.h"

/* security parameter declaration */
YACL_MODULE_DECLARE("rsa_sign", SecParam::C::k128, SecParam::S::INF);

namespace yacl::crypto {

// RSA sign with sha256 (wrapper for OpenSSL)
class RsaSigner final : public AsymmetricSigner {
 public:
  // constructors and destrucors
  explicit RsaSigner(openssl::UniquePkey&& sk) : sk_(std::move(sk)) {}
  explicit RsaSigner(/* pem key */ ByteContainerView sk_buf)
      : sk_(LoadKeyFromBuf(sk_buf)) {}

  // return the scheme name
  SignatureScheme GetSignatureSchema() const override { return scheme_; }

  // sign a message with stored private key
  std::vector<uint8_t> Sign(ByteContainerView message) const override;

 private:
  const openssl::UniquePkey sk_;
  const SignatureScheme scheme_ = SignatureScheme::RSA_SIGNING_SHA256_HASH;
};

// RSA verify with sha256 (wrapper for OpenSSL)
class RsaVerifier final : public AsymmetricVerifier {
 public:
  // constructors and destrucors
  explicit RsaVerifier(openssl::UniquePkey&& pk) : pk_(std::move(pk)) {}
  explicit RsaVerifier(/* pem key */ ByteContainerView pk_buf)
      : pk_(LoadKeyFromBuf(pk_buf)) {}

  // return the scheme name
  SignatureScheme GetSignatureSchema() const override { return scheme_; }

  // verify a message and its signature with stored public key
  bool Verify(ByteContainerView message,
              ByteContainerView signature) const override;

 private:
  const openssl::UniquePkey pk_;
  const SignatureScheme scheme_ = SignatureScheme::RSA_SIGNING_SHA256_HASH;
};

}  // namespace yacl::crypto
