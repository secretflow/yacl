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

#include "yacl/crypto/sign/rsa_signing.h"

#include <vector>

namespace yacl::crypto {

namespace {
// see: https://www.openssl.org/docs/man3.0/man3/RSA_public_encrypt.html
// RSA_PKCS1_OAEP_PADDING: EME-OAEP as defined in PKCS #1 v2.0 with SHA-1, MGF1
// and an empty encoding parameter. This mode is recommended for all new
// applications.
constexpr int kRsaPadding = RSA_PKCS1_PADDING;
}  // namespace

std::vector<uint8_t> RsaSigner::Sign(ByteContainerView message) const {
  // see: https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_sign.html
  auto ctx = openssl::UniquePkeyCtx(
      EVP_PKEY_CTX_new(sk_.get(), /* engine = default */ nullptr));
  YACL_ENFORCE(ctx != nullptr);

  // init context
  OSSL_RET_1(EVP_PKEY_sign_init(ctx.get()));

  // make sure to use OAEP_PADDING
  OSSL_RET_1(EVP_PKEY_CTX_set_rsa_padding(ctx.get(), kRsaPadding));

  // use sha256
  // EVP_PKEY_CTX_set_signature_md() sets the message digest type used in a
  // signature. It can be used in the RSA, DSA and ECDSA algorithms.
  OSSL_RET_1(EVP_PKEY_CTX_set_signature_md(ctx.get(), EVP_sha256()));

  // sha256 on the message
  auto md = Sha256(message);

  // first, get output length
  size_t outlen = 0;
  OSSL_RET_1(EVP_PKEY_sign(ctx.get(), /* empty input */ nullptr, &outlen,
                           md.data(), md.size()));

  // then sign
  std::vector<uint8_t> out(outlen);
  OSSL_RET_1(
      EVP_PKEY_sign(ctx.get(), out.data(), &outlen, md.data(), md.size()));

  return out;
}

bool RsaVerifier::Verify(ByteContainerView message,
                         ByteContainerView signature) const {
  // see: https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_sign.html
  auto ctx = openssl::UniquePkeyCtx(
      EVP_PKEY_CTX_new(pk_.get(), /* engine = default */ nullptr));
  YACL_ENFORCE(ctx != nullptr);

  // init context
  OSSL_RET_1(EVP_PKEY_verify_init(ctx.get()));

  // make sure to use OAEP_PADDING
  OSSL_RET_1(EVP_PKEY_CTX_set_rsa_padding(ctx.get(), kRsaPadding));

  // use sha256
  // EVP_PKEY_CTX_set_signature_md() sets the message digest type used in a
  // signature. It can be used in the RSA, DSA and ECDSA algorithms.
  OSSL_RET_1(EVP_PKEY_CTX_set_signature_md(ctx.get(), EVP_sha256()));

  // sha256 on the message
  auto md = Sha256(message);

  // verify and get the final result
  int ret = EVP_PKEY_verify(ctx.get(), signature.data(), signature.size(),
                            md.data(), md.size());
  YACL_ENFORCE(ret >= 0);  // ret = 0, verify fail; ret = 1, verify success
  return ret == 1;
}

}  // namespace yacl::crypto
