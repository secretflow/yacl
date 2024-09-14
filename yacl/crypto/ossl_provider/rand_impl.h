// Copyright 2023 Ant Group Co., Ltd.
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

#include "openssl/crypto.h"
#include "openssl/e_os2.h"
#include "openssl/err.h"
#include "openssl/params.h"
#include "openssl/proverr.h"
#include "openssl/rand.h"
#include "openssl/randerr.h"
#include "spdlog/spdlog.h"

#include "yacl/crypto/openssl_wrappers.h"
#include "yacl/crypto/rand/entropy_source/entropy_source.h"

namespace yc = yacl::crypto;

static OSSL_FUNC_rand_newctx_fn yacl_rand_ctx_new;
static OSSL_FUNC_rand_freectx_fn yacl_rand_ctx_free;
static OSSL_FUNC_rand_instantiate_fn yacl_rand_ctx_instantiate;
static OSSL_FUNC_rand_uninstantiate_fn yacl_rand_ctx_uninstantiate;
static OSSL_FUNC_rand_generate_fn yacl_rand_ctx_generate;
static OSSL_FUNC_rand_reseed_fn yacl_rand_ctx_reseed;
static OSSL_FUNC_rand_gettable_ctx_params_fn yacl_rand_ctx_gettable_ctx_params;
static OSSL_FUNC_rand_get_ctx_params_fn yacl_rand_ctx_get_ctx_params;
static OSSL_FUNC_rand_verify_zeroization_fn yacl_rand_ctx_verify_zeroization;
static OSSL_FUNC_rand_enable_locking_fn yacl_rand_ctx_enable_locking;
static OSSL_FUNC_rand_lock_fn yacl_rand_ctx_lock;
static OSSL_FUNC_rand_unlock_fn yacl_rand_ctx_unlock;
static OSSL_FUNC_rand_get_seed_fn yacl_rand_ctx_get_seed;
static OSSL_FUNC_rand_clear_seed_fn yacl_rand_ctx_clear_seed;

const OSSL_DISPATCH yacl_rand_prov_functions[] = {
    {OSSL_FUNC_RAND_NEWCTX, (void (*)(void))yacl_rand_ctx_new},
    {OSSL_FUNC_RAND_FREECTX, (void (*)(void))yacl_rand_ctx_free},
    {OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void))yacl_rand_ctx_instantiate},
    {OSSL_FUNC_RAND_UNINSTANTIATE, (void (*)(void))yacl_rand_ctx_uninstantiate},
    {OSSL_FUNC_RAND_GENERATE, (void (*)(void))yacl_rand_ctx_generate},
    {OSSL_FUNC_RAND_RESEED, (void (*)(void))yacl_rand_ctx_reseed},
    {OSSL_FUNC_RAND_ENABLE_LOCKING,
     (void (*)(void))yacl_rand_ctx_enable_locking},
    {OSSL_FUNC_RAND_LOCK, (void (*)(void))yacl_rand_ctx_lock},
    {OSSL_FUNC_RAND_UNLOCK, (void (*)(void))yacl_rand_ctx_unlock},
    {OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS,
     (void (*)(void))yacl_rand_ctx_gettable_ctx_params},
    {OSSL_FUNC_RAND_GET_CTX_PARAMS,
     (void (*)(void))yacl_rand_ctx_get_ctx_params},
    {OSSL_FUNC_RAND_VERIFY_ZEROIZATION,
     (void (*)(void))yacl_rand_ctx_verify_zeroization},
    {OSSL_FUNC_RAND_GET_SEED, (void (*)(void))yacl_rand_ctx_get_seed},
    {OSSL_FUNC_RAND_CLEAR_SEED, (void (*)(void))yacl_rand_ctx_clear_seed},
    /* OSSL_DISPATCH_END */ {0, nullptr}};

static const OSSL_PARAM yacl_rand_gettable_ctx_params[] = {
    OSSL_PARAM_int(OSSL_RAND_PARAM_STATE, NULL),
    OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, NULL),
    OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL), OSSL_PARAM_END};

// -------------------------------------------
// OpenSSL Seed Source Function Implementation
// -------------------------------------------

class RandProvider {
 public:
  int state;
};

// since this is the random source, there should be no parent
static void *yacl_rand_ctx_new(
    ossl_unused void *provider, void *parent,
    ossl_unused const OSSL_DISPATCH *parent_dispatch) {
  RandProvider *s;

  if (parent != nullptr) {
    ERR_raise(ERR_LIB_PROV, PROV_R_SEED_SOURCES_MUST_NOT_HAVE_A_PARENT);
    return nullptr;
  }

  s = static_cast<RandProvider *>(OPENSSL_zalloc(sizeof(*s)));

  if (s == nullptr) {
    return nullptr;
  }

  s->state = EVP_RAND_STATE_UNINITIALISED;
  return s;
}

static void yacl_rand_ctx_free(void *vseed) { OPENSSL_free(vseed); }

// OSSL_FUNC_rand_instantiate() is used to instantiate the DRBG ctx at a
// requested security strength. In addition, prediction_resistance can be
// requested. Additional input addin of length addin_len bytes can optionally be
// provided. The parameters specified in params configure the DRBG and these
// should be processed before instantiation.
//
// https://www.openssl.org/docs/man3.0/man7/provider-rand.html
static int yacl_rand_ctx_instantiate(void *vseed,
                                     ossl_unused unsigned int strength,
                                     ossl_unused int prediction_resistance,
                                     ossl_unused const unsigned char *pstr,
                                     ossl_unused size_t pstr_len,
                                     ossl_unused const OSSL_PARAM params[]) {
  auto *s = static_cast<RandProvider *>(vseed);

  s->state = EVP_RAND_STATE_READY;
  return 1;
}

// OSSL_FUNC_rand_uninstantiate() is used to uninstantiate the DRBG ctx. After
// being uninstantiated, a DRBG is unable to produce output until it is
// instantiated anew.
//
// https://www.openssl.org/docs/man3.0/man7/provider-rand.html
static int yacl_rand_ctx_uninstantiate(void *vseed) {
  auto *s = static_cast<RandProvider *>(vseed);

  s->state = EVP_RAND_STATE_UNINITIALISED;
  return 1;
}

static int yacl_rand_ctx_generate(void *vseed, unsigned char *out,
                                  size_t outlen,
                                  ossl_unused unsigned int strength,
                                  ossl_unused int prediction_resistance,
                                  ossl_unused const unsigned char *adin,
                                  ossl_unused size_t adin_len) {
  auto *s = static_cast<RandProvider *>(vseed);

  if (s->state != EVP_RAND_STATE_READY) {
    ERR_raise(ERR_LIB_PROV, s->state == EVP_RAND_STATE_ERROR
                                ? PROV_R_IN_ERROR_STATE
                                : PROV_R_NOT_INSTANTIATED);
    return 0;
  }

  /* core implementation */
  SPDLOG_INFO("Using Yacl's Random Entropy Source");
  auto es = yc::EntropySourceFactory::Instance().Create("auto");
  auto out_buf = es->GetEntropy(outlen);
  YACL_ENFORCE((size_t)out_buf.size() == outlen);
  std::memcpy(out, out_buf.data(), out_buf.size());

  return 1;
}

static int yacl_rand_ctx_reseed(void *vseed,
                                ossl_unused int prediction_resistance,
                                ossl_unused const unsigned char *ent,
                                ossl_unused size_t ent_len,
                                ossl_unused const unsigned char *adin,
                                ossl_unused size_t adin_len) {
  auto *s = static_cast<RandProvider *>(vseed);

  if (s->state != EVP_RAND_STATE_READY) {
    ERR_raise(ERR_LIB_PROV, s->state == EVP_RAND_STATE_ERROR
                                ? PROV_R_IN_ERROR_STATE
                                : PROV_R_NOT_INSTANTIATED);
    return 0;
  }
  return 1;
}

static int yacl_rand_ctx_get_ctx_params(void *vseed, OSSL_PARAM params[]) {
  auto *s = static_cast<RandProvider *>(vseed);
  OSSL_PARAM *p;

  p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE);
  if (p != nullptr && (OSSL_PARAM_set_int(p, s->state) == 0)) {
    return 0;
  }

  // copied from:
  // https://github.com/openssl/openssl/blob/master/providers/implementations/rands/seed_src.c#L148
  p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH);
  if (p != nullptr && (OSSL_PARAM_set_int(p, 1024) == 0)) {
    return 0;
  }

  p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
  if (p != nullptr && (OSSL_PARAM_set_size_t(p, 128) == 0)) {
    return 0;
  }
  return 1;
}

static const OSSL_PARAM *yacl_rand_ctx_gettable_ctx_params(
    ossl_unused void *vseed, ossl_unused void *provider) {
  return yacl_rand_gettable_ctx_params;
}

// OSSL_FUNC_rand_verify_zeroization() is used to determine if the internal
// state of the DRBG is zero. This capability is mandated by NIST as part of the
// self tests, it is unlikely to be useful in other circumstances.
//
// https://www.openssl.org/docs/man3.0/man7/provider-rand.html
static int yacl_rand_ctx_verify_zeroization(ossl_unused void *vseed) {
  return 1;
}

// OSSL_FUNC_rand_get_seed() is used by deterministic generators to obtain their
// seeding material from their parent. The seed bytes will meet the specified
// security level of entropy bits and there will be between min_len and max_len
// inclusive bytes in total. If prediction_resistance is true, the bytes will be
// produced from a live entropy source. Additional input addin of length
// addin_len bytes can optionally be provided. A pointer to the seed material is
// returned in *buffer and this must be freed by a later call to
// OSSL_FUNC_rand_clear_seed().
//
// https://www.openssl.org/docs/man3.0/man7/provider-rand.html
static size_t yacl_rand_ctx_get_seed(void *vseed, unsigned char **pout,
                                     ossl_unused int entropy, size_t min_len,
                                     ossl_unused size_t max_len,
                                     ossl_unused int prediction_resistance,
                                     const unsigned char *adin,
                                     size_t adin_len) {
  auto *s = static_cast<RandProvider *>(vseed);

  if (s->state != EVP_RAND_STATE_READY) {
    ERR_raise(ERR_LIB_PROV, s->state == EVP_RAND_STATE_ERROR
                                ? PROV_R_IN_ERROR_STATE
                                : PROV_R_NOT_INSTANTIATED);
    return 0;
  }

  // allocate storatge
  auto *buffer = static_cast<unsigned char *>(OPENSSL_secure_malloc(min_len));

  // gen entropy with min_len length
  // auto es = yc::EntropySourceFactory::Instance().Create("auto");
  // auto out_buf = es->GetEntropy(min_len);
  // std::memcpy(buffer, out_buf.data(), out_buf.size());
  *pout = buffer;

  /* xor the additional data into the output */
  for (size_t i = 0; i < adin_len; ++i) {
    (*pout)[i % min_len] ^= adin[i];
  }

  return min_len;
}

static void yacl_rand_ctx_clear_seed(ossl_unused void *vdrbg,
                                     unsigned char *out, size_t outlen) {
  OPENSSL_secure_clear_free(out, outlen);
}

static int yacl_rand_ctx_enable_locking(ossl_unused void *vseed) { return 1; }

int yacl_rand_ctx_lock(ossl_unused void *vctx) { return 1; }

void yacl_rand_ctx_unlock(ossl_unused void *vctx) {}