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

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "yacl/base/exception.h"
#include "yacl/crypto/ossl_provider/helper.h"
#include "yacl/secparam.h"

namespace yacl::crypto {

namespace {

std::vector<OSSL_PARAM> SelectParams(const std::string& type) {
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

OpensslDrbg::OpensslDrbg(std::string type,
                         const std::shared_ptr<EntropySource>& es)
    : Drbg(es), type_(std::move(type)) {
  // new entropy_source context
  openssl::UniqueRandCtx es_ctx = nullptr;

  // load openssl provider
  auto libctx = openssl::UniqueLib(OSSL_LIB_CTX_new());
  auto prov = openssl::UniqueProv(
      OSSL_PROVIDER_load(libctx.get(), GetProviderPath().c_str()));

  if (prov != nullptr) {
    // fetch provider's entropy_source algorithm
    auto es = openssl::UniqueRand(EVP_RAND_fetch(libctx.get(), "Yes", nullptr));
    YACL_ENFORCE(es != nullptr);

    // give es_ctx the fetched es algorithm
    es_ctx = openssl::UniqueRandCtx(EVP_RAND_CTX_new(es.get(), nullptr));
    YACL_ENFORCE(es_ctx != nullptr);

    // instantiate the es_ctx
    OSSL_RET_1(EVP_RAND_instantiate(es_ctx.get(), 128, 0, nullptr, 0, nullptr));
  } else {
    SPDLOG_WARN(
        "Yacl has been configured to use Yacl's entropy source, but unable "
        "to find one. Fallback to use openssl's default entropy srouce");
  }

  // fetch rand (drbg with the specified type) algorithm from OpenSSL's default
  // provider
  auto rand =
      openssl::UniqueRand(EVP_RAND_fetch(nullptr, type_.c_str(), nullptr));
  YACL_ENFORCE(rand != nullptr);

  // give ctx_ the fetched algorithm
  ctx_ = openssl::UniqueRandCtx(EVP_RAND_CTX_new(rand.get(), es_ctx.get()));
  YACL_ENFORCE(ctx_ != nullptr);

  // setup parameters
  const unsigned int c = YACL_MODULE_SECPARAM_C_UINT("drbg");
  OSSL_RET_1(EVP_RAND_instantiate(ctx_.get(), c, 0, nullptr, 0,
                                  SelectParams(type_).data()));
  OSSL_RET_1(EVP_RAND_enable_locking(ctx_.get()));
}

OpensslDrbg::~OpensslDrbg() = default;

void OpensslDrbg::Fill(char* buf, size_t len) {
  const unsigned int c = YACL_MODULE_SECPARAM_C_UINT("drbg");
  YACL_ENFORCE(EVP_RAND_get_state(ctx_.get()) == EVP_RAND_STATE_READY);
  YACL_ENFORCE(EVP_RAND_generate(ctx_.get(), (unsigned char*)buf, len, c, 0,
                                 nullptr, 0) > 0);
}

void OpensslDrbg::ReSeed() {
  // from https://www.openssl.org/docs/man3.1/man7/EVP_RAND.html
  //
  // Automatic Reseeding: Before satisfying a generate request
  // (EVP_RAND_generate(3)), the DRBG reseeds itself automatically under
  // predefined circumstances.
  //
  // Manual Reseeding: the caller can request an immediate reseeding of the DRBG
  // with fresh entropy by setting the prediction resistance parameter to 1 when
  // calling EVP_RAND_generate(3).
  const unsigned int c = YACL_MODULE_SECPARAM_C_UINT("drbg");
  YACL_ENFORCE(EVP_RAND_get_state(ctx_.get()) == EVP_RAND_STATE_READY);
  YACL_ENFORCE(EVP_RAND_generate(ctx_.get(), nullptr, 0, c,
                                 /* prediction resistance flag */ 1, nullptr,
                                 0) > 0);
}

REGISTER_DRBG_LIBRARY("OpenSSL", 100, OpensslDrbg::Check, OpensslDrbg::Create);

}  // namespace yacl::crypto
