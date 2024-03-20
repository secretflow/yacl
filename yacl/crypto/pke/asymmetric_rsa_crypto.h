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
#include <utility>
#include <vector>

#include "yacl/crypto/key_utils.h"
#include "yacl/crypto/pke/asymmetric_crypto.h"
#include "yacl/secparam.h"

/* security parameter declaration */
YACL_MODULE_DECLARE("rsa_enc", SecParam::C::k128, SecParam::S::INF);

namespace yacl::crypto {

// RSA with OAEP
class RsaEncryptor : public AsymmetricEncryptor {
 public:
  explicit RsaEncryptor(openssl::UniquePkey&& pk) : pk_(std::move(pk)) {}
  explicit RsaEncryptor(/* pem key */ ByteContainerView pk_buf)
      : pk_(LoadKeyFromBuf(pk_buf)) {}

  AsymCryptoSchema GetSchema() const override { return schema_; }
  std::vector<uint8_t> Encrypt(ByteContainerView plaintext) override;

 private:
  const openssl::UniquePkey pk_;
  const AsymCryptoSchema schema_ = AsymCryptoSchema::RSA2048_OAEP;
};

class RsaDecryptor : public AsymmetricDecryptor {
 public:
  explicit RsaDecryptor(openssl::UniquePkey&& sk) : sk_(std::move(sk)) {}
  explicit RsaDecryptor(/* pem key */ ByteContainerView sk_buf)
      : sk_(LoadKeyFromBuf(sk_buf)) {}

  AsymCryptoSchema GetSchema() const override { return schema_; }
  std::vector<uint8_t> Decrypt(ByteContainerView ciphertext) override;

 private:
  const openssl::UniquePkey sk_;
  const AsymCryptoSchema schema_ = AsymCryptoSchema::RSA2048_OAEP;
};

}  // namespace yacl::crypto
