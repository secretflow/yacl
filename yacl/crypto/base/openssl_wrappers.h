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
#include <string>
#include <unordered_map>

#include "hash/hash_interface.h" /* yacl hash to openssl hash */
#include "openssl/bio.h"
#include "openssl/bn.h"
#include "openssl/core.h"
#include "openssl/core_dispatch.h"
#include "openssl/core_names.h"
#include "openssl/decoder.h"
#include "openssl/ec.h"
#include "openssl/encoder.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/provider.h"
#include "openssl/x509v3.h"

#include "yacl/base/byte_container_view.h"
#include "yacl/utils/scope_guard.h"

namespace yacl::crypto::openssl {

namespace internal {

// cpp-17+
template <auto DeleteFn>
struct FunctionDeleter {
  template <class T>
  void operator()(T* ptr) {
    DeleteFn(ptr);
  }
};

template <class T, auto DeleteFn>
using TyHelper = std::unique_ptr<T, FunctionDeleter<DeleteFn>>;

}  // namespace internal

// ------------------------
// OpenSSL Pointer Wrappers
// ------------------------

/* message digests */
using UniqueMd = internal::TyHelper<EVP_MD, EVP_MD_free>;
using UniqueMdCtx = internal::TyHelper<EVP_MD_CTX, EVP_MD_CTX_free>;

/* openssl3 unifies the interfaces of mac and hmac */
using UniqueMac = internal::TyHelper<EVP_MAC, EVP_MAC_free>;
using UniqueMacCtx = internal::TyHelper<EVP_MAC_CTX, EVP_MAC_CTX_free>;

/* random */
using UniqueRand = internal::TyHelper<EVP_RAND, EVP_RAND_free>;
using UniqueRandCtx = internal::TyHelper<EVP_RAND_CTX, EVP_RAND_CTX_free>;

/* block ciphers */
using UniqueCipher = internal::TyHelper<EVP_CIPHER, EVP_CIPHER_free>;
using UniqueCipherCtx = internal::TyHelper<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free>;

using UniqueParam = internal::TyHelper<OSSL_PARAM, OSSL_PARAM_free>;

/* encoding and decodings */
using UniqueBio = internal::TyHelper<BIO, BIO_free>;
using UniqueX509 = internal::TyHelper<X509, X509_free>;
using UniqueX509Ext = internal::TyHelper<X509_EXTENSION, X509_EXTENSION_free>;

using UniquePkey = internal::TyHelper<EVP_PKEY, EVP_PKEY_free>;
using UniquePkeyCtx = internal::TyHelper<EVP_PKEY_CTX, EVP_PKEY_CTX_free>;
using UniqueEncoder =
    internal::TyHelper<OSSL_ENCODER_CTX, OSSL_ENCODER_CTX_free>;
using UniqueDecoder =
    internal::TyHelper<OSSL_DECODER_CTX, OSSL_DECODER_CTX_free>;

/* provider lib */
using UniqueLib = internal::TyHelper<OSSL_LIB_CTX, OSSL_LIB_CTX_free>;
using UniqueProv = internal::TyHelper<OSSL_PROVIDER, OSSL_PROVIDER_unload>;

/* ec and bn */
using UniqueEcGroup = internal::TyHelper<EC_GROUP, EC_GROUP_free>;
using UniqueBnCtx = internal::TyHelper<BN_CTX, BN_CTX_free>;
using UniqueBn = internal::TyHelper<BIGNUM, BN_free>;

// ------------------
// OpenSSL EVP Enum
// ------------------
inline UniqueMd FetchEvpMd(const std::string& md_str) {
  return UniqueMd(EVP_MD_fetch(nullptr, md_str.c_str(), nullptr));
}

inline UniqueCipher FetchEvpCipher(const std::string& cipher_str) {
  return UniqueCipher(EVP_CIPHER_fetch(nullptr, cipher_str.c_str(), nullptr));
}

inline UniqueMac FetchEvpHmac() {
  return UniqueMac(EVP_MAC_fetch(nullptr, OSSL_MAC_NAME_HMAC, nullptr));
}

// see: https://en.wikibooks.org/wiki/OpenSSL/Error_handling
inline std::string GetOSSLErr() {
  BIO* bio = BIO_new(BIO_s_mem());
  ERR_print_errors(bio);
  char* buf;
  size_t len = BIO_get_mem_data(bio, &buf);
  std::string ret(buf, len);
  BIO_free(bio);
  return ret;
}

// ---------------------------------
// Helpers for OpenSSL return values
// ---------------------------------
/* enforce return code == 1 */
#define OSSL_RET_1(MP_ERR, ...) YACL_ENFORCE_EQ((MP_ERR), 1, __VA_ARGS__)

}  // namespace yacl::crypto::openssl
