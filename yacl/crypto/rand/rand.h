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

#include <algorithm>
#include <climits>
#include <cstdint>
#include <memory>
#include <random>
#include <type_traits>
#include <vector>

#include "yacl/base/dynamic_bitset.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/openssl_wrappers.h"
#include "yacl/crypto/rand/drbg/drbg.h"
#include "yacl/secparam.h"

namespace yacl::crypto {

// -------------------------
// Generic Randomness Func
// -------------------------

// Fill randomness to buf with len within the default random engine.
//
// NOTE: this function is the core of yacl's random generator, all other
// functions below use this function to generate associate randomness for each
// own purporse.
void FillRand(char *buf, size_t len, bool fast_mode = false);

// --------------------------------
// Random Support for Generic Types
// --------------------------------

// Generate uint64_t random value
uint64_t RandU64(bool fast_mode = false);

// Generate uint64_t random value, in a faster but less secure way
inline uint64_t FastRandU64() { return RandU64(true); }

// Generate uint64_t random value, in a slower but more secure way
// (randomness comes directly from an random entropy source)
inline uint64_t SecureRandU64() { return RandU64(false); }

// Generate uint128_t random value
uint128_t RandU128(bool fast_mode = false);

// Generate uint128_t random value, in a faster but less secure way
inline uint128_t FastRandU128() { return RandU128(true); }

// Generate uint128_t random value, in a slower but more secure way
// (randomness comes directly from an random entropy source)
inline uint128_t SecureRandU128() { return RandU128(false); }

// Function alias
inline uint128_t RandSeed(bool fast_mode = false) { return RandU64(fast_mode); }
inline uint128_t FastRandSeed() { return FastRandU128(); }
inline uint128_t SecureRandSeed() { return SecureRandU128(); }

// Generate random number of bytes
std::vector<uint8_t> RandBytes(uint64_t len, bool fast_mode = false);
std::vector<uint8_t> FastRandBytes(uint64_t len);
std::vector<uint8_t> SecureRandBytes(uint64_t len);

// wanring: the output may not be strictly uniformly random
// FIXME(@shanzhu.cjm) Improve performance
inline uint32_t RandInRange(uint32_t n) {
  uint32_t tmp = FastRandU64();
  return tmp % n;
}
template <typename T = uint128_t,
          std::enable_if_t<std::is_integral_v<T>, int> = 0>
inline T RandLtN(T n) {
  // see: nist-sp800-90A, Appendix A.5.3
  // efficiency: constant-round
  auto required_size =
      sizeof(T) + (YACL_MODULE_SECPARAM_S_UINT("rand") + 7) / 8;
  auto rand_bytes = SecureRandBytes(required_size);
  math::MPInt r;
  r.FromMagBytes(rand_bytes, Endian::little);
  math::MPInt::Mod(r, math::MPInt(n), &r);
  return r.Get<T>();
}
// -----------------------------
// Random Support for Yacl Types
// -----------------------------
// Generate rand bits for either vector<bool> or dynamic_bitset<T>
// where T = {uint128_t, uint64_t, uint32_t, uint16_t}
template <typename T>
struct IsSupportedBitVectorType
    : public std::disjunction<std::is_same<std::vector<bool>, T>,
                              is_dynamic_bitset_type<T>> {};

template <typename T = dynamic_bitset<uint128_t>,
          std::enable_if_t<IsSupportedBitVectorType<T>::value, bool> = true>
T RandBits(uint64_t len, bool fast_mode = false);

template <typename T = dynamic_bitset<uint128_t>,
          std::enable_if_t<IsSupportedBitVectorType<T>::value, bool> = true>
inline T FastRandBits(uint64_t len) {
  return RandBits<T>(len, true);
}

// Generate rand bits in a secure but slow way
template <typename T = dynamic_bitset<uint128_t>,
          std::enable_if_t<IsSupportedBitVectorType<T>::value, bool> = true>
inline T SecureRandBits(uint64_t len) {
  return RandBits<T>(len, false);
}

// Generate random T-type vectors
template <typename T, std::enable_if_t<std::is_standard_layout_v<T>, int> = 0>
inline std::vector<T> RandVec(uint64_t len, bool fast_mode = false) {
  std::vector<T> out(len);
  FillRand((char *)out.data(), sizeof(T) * len, fast_mode);
  return out;
}

}  // namespace yacl::crypto
