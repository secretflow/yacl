// Copyright 2023 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <memory>

#include "gtest/gtest.h"
#include "openssl/crypto.h"
#include "openssl/e_os2.h"
#include "openssl/err.h"
#include "openssl/params.h"
#include "openssl/proverr.h"
#include "openssl/rand.h"
#include "openssl/randerr.h"

#include "yacl/crypto/openssl_wrappers.h"
#include "yacl/crypto/ossl-provider/helper.h"

namespace yacl::crypto {

TEST(OpensslTest, ShouldWork) {
  auto libctx = openssl::UniqueLib(OSSL_LIB_CTX_new());

  // OSSL_PROVIDER_load() loads and initializes a provider. This may simply
  // initialize a provider that was previously added with
  auto prov = openssl::UniqueProv(
      OSSL_PROVIDER_load(libctx.get(), GetProviderPath().c_str()));
  YACL_ENFORCE(prov != nullptr, ERR_error_string(ERR_get_error(), nullptr));

  // get provider's entropy source EVP_RAND* rand;
  auto* yes = EVP_RAND_fetch(libctx.get(), "Yes",
                             nullptr); /* yes = yacl entropy source */

  YACL_ENFORCE(yes != nullptr, ERR_error_string(ERR_get_error(), nullptr));
  auto* yes_ctx = EVP_RAND_CTX_new(yes, nullptr);
  YACL_ENFORCE(yes_ctx != nullptr);
  EVP_RAND_instantiate(yes_ctx, 128, 0, nullptr, 0, nullptr);

  /* Feed seed into a DRBG */
  EVP_RAND* rand = EVP_RAND_fetch(nullptr, "CTR-DRBG", nullptr);
  auto* rctx = EVP_RAND_CTX_new(rand, yes_ctx);

  /* Configure the DRBG */
  unsigned char bytes[20];
  OSSL_PARAM params[2];
  OSSL_PARAM* p = params;
  *p++ = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER,
                                          (char*)"aes-256-ctr", 0);
  *p = OSSL_PARAM_construct_end();
  auto ret = EVP_RAND_instantiate(rctx, 128, 0, nullptr, 0, params);
  EXPECT_EQ(ret, 1);

  // EVP_RAND_generate() produces random bytes from the RAND ctx with the
  // additional input addin of length addin_len. The bytes produced will meet
  // the security strength. If prediction_resistance is specified, fresh
  // entropy from a live source will be sought. This call operates as per
  // NIST SP 800-90A and SP 800-90C.
  auto ret1 = EVP_RAND_generate(rctx, bytes, sizeof(bytes), 128, 0, nullptr, 0);
  EXPECT_EQ(ret1, 1);

  EVP_RAND_free(yes); /* free */
  EVP_RAND_CTX_free(yes_ctx);
  EVP_RAND_free(rand); /* free */
  EVP_RAND_CTX_free(rctx);
}

//   https://www.openssl.org/docs/man3.0/man7/EVP_RAND-SEED-SRC.html
TEST(OpensslTest, Example1) {
  EVP_RAND* rand;
  EVP_RAND_CTX* seed;
  EVP_RAND_CTX* rctx;
  unsigned char bytes[100];
  OSSL_PARAM params[2];
  OSSL_PARAM* p = params;
  unsigned int strength = 128;

  /* Create a seed source */
  rand = EVP_RAND_fetch(nullptr, "SEED-SRC", nullptr);
  seed = EVP_RAND_CTX_new(rand, nullptr);
  EVP_RAND_instantiate(seed, 128, 0, nullptr, 0, nullptr);

  /* Feed this into a DRBG */
  auto* tmp = EVP_RAND_fetch(nullptr, "CTR-DRBG", nullptr);
  // EVP_RAND_CTX_new() creates a new context for the RAND implementation rand.
  // If not NULL, parent specifies the seed source for this implementation.
  rctx = EVP_RAND_CTX_new(tmp, seed);
  YACL_ENFORCE(rctx != nullptr);

  /* Configure the DRBG */
  *p++ = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER,
                                          (char*)"AES-256-CTR", 0);
  *p = OSSL_PARAM_construct_end();
  EVP_RAND_instantiate(rctx, strength, 0, nullptr, 0, params);

  int ret =
      EVP_RAND_generate(rctx, bytes, sizeof(bytes), strength, 0, nullptr, 0);
  EXPECT_EQ(ret, 1);

  EVP_RAND_free(rand);
  EVP_RAND_free(tmp);
  EVP_RAND_CTX_free(rctx);
  EVP_RAND_CTX_free(seed);
}

// https://www.openssl.org/docs/man3.0/man7/EVP_RAND-CTR-DRBG.html
TEST(OpensslTest, Example2) {
  EVP_RAND* rand;
  EVP_RAND_CTX* rctx;
  unsigned char bytes[100];
  OSSL_PARAM params[2];
  OSSL_PARAM* p = params;
  unsigned int strength = 128;

  rand = EVP_RAND_fetch(nullptr, "CTR-DRBG", nullptr);
  rctx = EVP_RAND_CTX_new(rand, nullptr);

  *p++ = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER,
                                          (char*)"AES-256-CTR", 0);
  *p = OSSL_PARAM_construct_end();
  int ret0 = EVP_RAND_instantiate(rctx, strength, 0, nullptr, 0, params);
  EXPECT_EQ(ret0, 1);

  int ret1 =
      EVP_RAND_generate(rctx, bytes, sizeof(bytes), strength, 0, nullptr, 0);
  EXPECT_EQ(ret1, 1);

  EVP_RAND_free(rand);
  EVP_RAND_CTX_free(rctx);
}

}  // namespace yacl::crypto
