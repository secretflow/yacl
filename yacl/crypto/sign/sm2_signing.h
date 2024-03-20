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
YACL_MODULE_DECLARE("sm2_sign", SecParam::C::k128, SecParam::S::INF);

namespace yacl::crypto {

class Sm2Signer final : public AsymmetricSigner {
 public:
  // constructors and destrucors
  explicit Sm2Signer(openssl::UniquePkey&& sk) : sk_(std::move(sk)) {}
  explicit Sm2Signer(/* pem key */ ByteContainerView sk_buf)
      : sk_(LoadKeyFromBuf(sk_buf)) {}

  SignatureScheme GetSignatureSchema() const override { return scheme_; }

  // Sign message with the default id.
  std::vector<uint8_t> Sign(ByteContainerView message) const override;

 private:
  const openssl::UniquePkey sk_;
  const SignatureScheme scheme_ = SignatureScheme::SM2_SIGNING_SM3_HASH;
};

// SM2 verify with SM3 (wrapper for OpenSSL)
class Sm2Verifier final : public AsymmetricVerifier {
 public:
  // constructors and destrucors
  explicit Sm2Verifier(openssl::UniquePkey&& pk) : pk_(std::move(pk)) {}
  explicit Sm2Verifier(/* pem key */ ByteContainerView pk_buf)
      : pk_(LoadKeyFromBuf(pk_buf)) {}

  // return the scheme name
  SignatureScheme GetSignatureSchema() const override { return scheme_; }

  // verify a message and its signature with stored public key
  bool Verify(ByteContainerView message,
              ByteContainerView signature) const override;

 private:
  const openssl::UniquePkey pk_;
  const SignatureScheme scheme_ = SignatureScheme::SM2_SIGNING_SM3_HASH;
};

// TODO(@raofei, @shanzhu): support sm2 certificate

}  // namespace yacl::crypto
