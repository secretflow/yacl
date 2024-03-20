// Copyright 2022 Ant Group Co., Ltd.
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

#include "yacl/crypto/hmac/hmac.h"

#include "yacl/base/exception.h"
#include "yacl/crypto/openssl_wrappers.h"

namespace yacl::crypto {

Hmac::Hmac(HashAlgorithm hash_algo, ByteContainerView key)
    : hash_algo_(hash_algo), key_(key.begin(), key.end()) {
  mac_ = openssl::FetchEvpHmac();
  ctx_ = openssl::UniqueMacCtx(EVP_MAC_CTX_new(mac_.get()));
  YACL_ENFORCE(ctx_ != nullptr);

  // Set up the underlying context ctx with information given via the key
  // and params arguments
  std::array<OSSL_PARAM, 2> params;
  params[0] = OSSL_PARAM_construct_utf8_string(
      "digest", const_cast<char*>(ToString(hash_algo)),
      /* the length of previous param is determined using strlen() */ 0);
  params[1] = OSSL_PARAM_construct_end();
  OSSL_RET_1(EVP_MAC_init(ctx_.get(), key_.data(), key_.size(),
                          /* params */ params.data()));
}

HashAlgorithm Hmac::GetHashAlgorithm() const { return hash_algo_; }

Hmac& Hmac::Reset() {
  YACL_ENFORCE(mac_ != nullptr);
  const auto* params = EVP_MAC_gettable_ctx_params(mac_.get());
  YACL_ENFORCE(params != nullptr);

  // re-init the mac context
  OSSL_RET_1(EVP_MAC_init(ctx_.get(), key_.data(), key_.size(),
                          /* params */ params));
  return *this;
}

Hmac& Hmac::Update(ByteContainerView data) {
  YACL_ENFORCE(ctx_ != nullptr);
  OSSL_RET_1(EVP_MAC_update(ctx_.get(), data.data(), data.size()));
  return *this;
}

std::vector<uint8_t> Hmac::CumulativeMac() const {
  YACL_ENFORCE(ctx_ != nullptr);
  // Do not finalize the internally stored hash context. Instead, finalize a
  // copy of the current context so that the current context can be updated in
  // future calls to Update.
  auto ctx_copy = openssl::UniqueMacCtx(EVP_MAC_CTX_dup(ctx_.get()));
  YACL_ENFORCE(ctx_copy != nullptr);

  // get the outptut size
  size_t outlen = 0;
  OSSL_RET_1(EVP_MAC_final(ctx_copy.get(), nullptr, &outlen, 0));

  // get the final output
  std::vector<uint8_t> mac(outlen);
  OSSL_RET_1(EVP_MAC_final(ctx_copy.get(), mac.data(), &outlen, mac.size()));
  mac.resize(outlen);  // this is necessary

  return mac;
}

}  // namespace yacl::crypto
