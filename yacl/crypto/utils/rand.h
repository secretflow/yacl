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

#include <algorithm>
#include <cstdint>
#include <random>
#include <type_traits>
#include <vector>

#include "absl/types/span.h"

#include "yacl/base/dynamic_bitset.h"
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
// insecure mode: gen (with openssl rand_bytes)
uint64_t RandU64(bool use_secure_rand = false);

inline uint64_t SecureRandU64() { return RandU64(true); }

// Generate uint128_t random value
// secure mode: reseed (with drbg mode kNistAesCtrDrbg), and gen (with openssl)
// insecure mode: gen (with openssl rand_bytes)
uint128_t RandU128(bool use_secure_rand = false);

inline uint128_t SecureRandU128() { return RandU128(true); }

// Generate uint128_t random seed (internally calls RandU128())
inline uint128_t RandSeed(bool use_secure_rand = false) {
  return RandU128(use_secure_rand);
}

inline uint128_t SecureRandSeed() { return RandSeed(true); }

// Generate rand bits for
//  - vector<bool>
//  - dynamic_bitset<T>, where T = {uint128_t, uint64_t, uint32_t, uint16_t}
// secure mode: prg.gen (with drbg mode kNistAesCtrDrbg)
// insecure mode: prg.gen (with drbg mode kAesEcb)
template <typename T>
struct is_supported_bit_vector_type
    : public std::disjunction<std::is_same<std::vector<bool>, T>,
                              is_dynamic_bitset_type<T>> {};

template <typename T = dynamic_bitset<uint128_t>,
          std::enable_if_t<is_supported_bit_vector_type<T>::value, bool> = true>
T RandBits(uint64_t len, bool use_secure_rand = false);

template <typename T = dynamic_bitset<uint128_t>,
          std::enable_if_t<is_supported_bit_vector_type<T>::value, bool> = true>
inline T SecureRandBits(uint64_t len) {
  return RandBits(len, true);
}

// Fill random type-T
// secure mode: RAND_priv_bytes (from openssl)
// insecure mode: RAND_bytes (from openssl)
template <typename T,
          std::enable_if_t<std::is_standard_layout<T>::value, int> = 0>
inline void FillRand(absl::Span<T> out, bool use_secure_rand = false) {
  const uint64_t nbytes = out.size() * sizeof(T);
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
template <typename T, std::enable_if_t<std::is_standard_layout_v<T>, int> = 0>
inline std::vector<T> RandVec(uint64_t len, bool use_secure_rand = false) {
  std::vector<T> out(len);
  FillRand(absl::MakeSpan(out), use_secure_rand);
  return out;
}

// Generate random number of bytes
inline std::vector<uint8_t> RandBytes(uint64_t len,
                                      bool use_secure_rand = false) {
  return RandVec<uint8_t>(len, use_secure_rand);
}

inline std::vector<uint8_t> SecureRandBytes(uint64_t len) {
  return RandBytes(len, true);
}

// wanring: the output may not be strictly uniformly random
inline uint32_t RandInRange(uint32_t n) {
  Prg<uint32_t> gen(RandSeed());
  return gen() % n;
}

inline std::vector<uint64_t> MakeRegularRandChoices(uint64_t t, uint64_t n) {
  const auto bin_size = (n + t - 1) / t;
  std::vector<uint64_t> out(t);
  for (uint64_t i = 0; i < t; i++) {
    const uint64_t limit = std::min(bin_size, n - i * bin_size);
    out[i] = RandInRange(limit) + i * bin_size;
  }
  return out;
}

// TODO(shanzhu) RFC: add more generic random interface, e.g.
//        void FillRand(RandContext* ctx, char* buf, uint64_t len);

}  // namespace yacl::crypto
