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

#include "yacl/crypto/rand/drbg/openssl_factory.h"

#include <algorithm>
#include <array>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "yacl/base/exception.h"
#include "yacl/crypto/ossl-provider/helper.h"
#include "yacl/secparam.h"

namespace yacl::crypto {

namespace {

std::vector<OSSL_PARAM> SelectParams(const std::string& type, SecParam::C c) {
  YACL_ENFORCE(c <= SecParam::C::k256);
  if (type == "CTR-DRBG") {
    std::vector<OSSL_PARAM> params(2);
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER,
                                                 (char*)SN_aes_256_ctr, 0);
    params[1] = OSSL_PARAM_construct_end();
    return params;
  } else if (type == "HASH-DRBG") {
    std::vector<OSSL_PARAM> params(2);
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_DIGEST,
                                                 (char*)SN_sha256, 0);
    params[1] = OSSL_PARAM_construct_end();
    return params;

  } else if (type == "HMAC-DRBG") {
    std::vector<OSSL_PARAM> params(3);
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_MAC,
                                                 (char*)SN_hmac, 0);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_DIGEST,
                                                 (char*)SN_sha256, 0);
    params[2] = OSSL_PARAM_construct_end();
    return params;

  } else {
    YACL_THROW("unknown drbg type!");
  }
}

}  // namespace

OpensslDrbg::OpensslDrbg(std::string type, bool use_yacl_es,
                         SecParam::C secparam)
    : Drbg(use_yacl_es), type_(std::move(type)), secparam_(secparam) {
  openssl::UniqueRandCtx seed = nullptr;
  if (use_yacl_es) {
    auto libctx = openssl::UniqueLib(OSSL_LIB_CTX_new());
    auto prov = openssl::UniqueProv(
        OSSL_PROVIDER_load(libctx.get(), GetProviderPath().c_str()));
    if (prov != nullptr) {
      // get provider's entropy source
      auto rand =
          openssl::UniqueRand(EVP_RAND_fetch(libctx.get(), "Yes", nullptr));
      YACL_ENFORCE(rand != nullptr);
      seed = openssl::UniqueRandCtx(EVP_RAND_CTX_new(rand.get(), nullptr));
      YACL_ENFORCE(seed != nullptr);
      YACL_ENFORCE(
          EVP_RAND_instantiate(seed.get(), 128, 0, nullptr, 0, nullptr) > 0);
    } else {
      SPDLOG_WARN(
          "Yacl has been configured to use Yacl's entropy source, but unable "
          "to find one. Fallback to use openssl's default entropy srouce");
    }
  }

  auto rand =
      openssl::UniqueRand(EVP_RAND_fetch(nullptr, type_.c_str(), nullptr));
  YACL_ENFORCE(rand != nullptr);

  ctx_ = openssl::UniqueRandCtx(EVP_RAND_CTX_new(rand.get(), seed.get()));
  YACL_ENFORCE(ctx_ != nullptr);

  // setup parameters
  YACL_ENFORCE(EVP_RAND_instantiate(
                   ctx_.get(),
                   static_cast<unsigned int>(SecParam::MakeInt(secparam_)), 0,
                   nullptr, 0, SelectParams(type_, c_).data()) > 0);
  YACL_ENFORCE(EVP_RAND_enable_locking(ctx_.get()) > 0);
}

OpensslDrbg::~OpensslDrbg() = default;

void OpensslDrbg::Fill(char* buf, size_t len) {
  YACL_ENFORCE(EVP_RAND_get_state(ctx_.get()) == EVP_RAND_STATE_READY);
  YACL_ENFORCE(EVP_RAND_generate(ctx_.get(), (unsigned char*)buf, len,
                                 SecParam::MakeInt(secparam_), 0, nullptr,
                                 0) > 0);
}

}  // namespace yacl::crypto
