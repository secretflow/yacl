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

#pragma once

#include <openssl/rand.h>

#include <random>
#include <vector>

#include "absl/types/span.h"

#include "yacl/base/exception.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/base/symmetric_crypto.h"
#include "yacl/crypto/tools/prg.h"

// Utility for randomness (not pseudo-randomness)
//
// We recommend applicaitons to set "use_secure_rand = true", which internally
// use DRBG to generate randomness. To generate seeded pseudorandomness,
// please use yacl/crypto-tools/prg.h. For more details of how DRBG works, see
// yacl/crypto/drbg/nist_aes_drbg.h
//
// * security strength = 128 bit (openssl=256, our drbg=128)

namespace yacl::crypto {

// Generate uint64_t random value
// secure mode: reseed (with drbg mode kNistAesCtrDrbg), and gen (with openssl)
// insecure mode: gen (with random_device)
uint64_t RandU64(bool use_secure_rand = false);

// Generate uint128_t random value
// secure mode: reseed (with drbg mode kNistAesCtrDrbg), and gen (with openssl)
// insecure mode: gen (with random_device)
uint128_t RandU128(bool use_secure_rand = false);

// Generate uint128_t random seed (internally calls RandU128())
inline uint128_t RandSeed(bool use_secure_rand = true) {
  return RandU128(use_secure_rand);
}

// Generate std::vector<bool> random bits
// secure mode: prg.gen (with drbg mode kNistAesCtrDrbg)
// insecure mode: prg.gen (with drbg mode kAesEcb)
// TODO(shanzhu): check the efficiency between drbg-prg and RAND_bytes
std::vector<bool> RandBits(size_t len, bool use_secure_rand = false);

// Fill random type-T
// secure mode: RAND_priv_bytes (from openssl)
// insecure mode: RAND_bytes (from openssl)
template <typename T,
          std::enable_if_t<std::is_standard_layout<T>::value, int> = 0>
inline void FillRand(absl::Span<T> out, bool use_secure_rand = false) {
  const size_t nbytes = out.size() * sizeof(T);
  if (use_secure_rand) {
    YACL_ENFORCE(
        RAND_priv_bytes(reinterpret_cast<uint8_t*>(out.data()), nbytes) == 1);
  } else {
    YACL_ENFORCE(RAND_bytes(reinterpret_cast<uint8_t*>(out.data()), nbytes) ==
                 1);
  }
}

// Generate random T-type vectors
// Note: The output is `sizeof(T)` bytes aligned.
template <typename T, std::enable_if_t<std::is_scalar<T>::value, int> = 0>
inline std::vector<T> RandVec(size_t len, bool use_secure_rand = false) {
  std::vector<T> out(len);
  FillRand(absl::MakeSpan(out), use_secure_rand);
  return out;
}

// Generate random number of bytes
inline std::vector<uint8_t> RandBytes(size_t len,
                                      bool use_secure_rand = false) {
  std::vector<uint8_t> out(len);
  FillRand<uint8_t>(absl::MakeSpan(out), use_secure_rand);
  return out;
}

// TODO(shanzhu) RFC: add more generic random interface, e.g.
//        void FillRand(RandContext* ctx, char* buf, size_t len);

}  // namespace yacl::crypto
