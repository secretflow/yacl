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
#include <limits>
#include <memory>
#include <random>
#include <type_traits>
#include <vector>

#include "yacl/base/dynamic_bitset.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/block_cipher/symmetric_crypto.h"
#include "yacl/crypto/openssl_wrappers.h"
#include "yacl/crypto/rand/drbg/drbg.h"
#include "yacl/crypto/tools/prg.h"
#include "yacl/math/mpint/mp_int.h"
#include "yacl/secparam.h"

/* security parameter declaration */
YACL_MODULE_DECLARE("rand", SecParam::C::k128, SecParam::S::k64);

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

// Generate uint32_t random value
uint32_t RandU32(bool fast_mode = false);

// Generate uint32_t random value, in a faster but less secure way
inline uint32_t FastRandU32() { return RandU32(true); }

// Generate uint32_t random value, in a slower but more secure way
// (randomness comes directly from an random entropy source)
inline uint32_t SecureRandU32() { return RandU32(false); }

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

// Generate random T-type vectors in fast mode
template <typename T, std::enable_if_t<std::is_standard_layout_v<T>, int> = 0>
inline std::vector<T> FastRandVec(uint64_t len) {
  return RandVec<T>(len, true);
}

// Generate random T-type vectors in secure mode
template <typename T, std::enable_if_t<std::is_standard_layout_v<T>, int> = 0>
inline std::vector<T> SecureRandVec(uint64_t len) {
  return RandVec<T>(len, false);
}

// -----------------------------------
// Random Support for Integral Numbers
// -----------------------------------

// warning: the output may not be strictly uniformly random
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

// Implementation of standard (cpp) UniformRandomBitGenerator
//
// see: https://en.cppreference.com/w/cpp/named_req/UniformRandomBitGenerator
//
// This implementation is provided to be used as the random bit source of
// std::shuffle. std::shuffle should internally call YaclStdUrbd with
// std::uniform_int_distribution, which again internally uses the method defined
// in A.5.1 of SP800-90A (reviewed on MacOS with libc++).
//
template <typename T, std::enable_if_t<std::is_unsigned_v<T>, bool> = true>
class YaclStdUrbg {
 public:
  using result_type = T;
  YaclStdUrbg() { drbg_ = DrbgFactory::Instance().Create("ctr-drbg"); };

  static constexpr T min() { return std::numeric_limits<T>::min(); }
  static constexpr T max() { return std::numeric_limits<T>::max(); }

  T operator()() {
    T ret;
    drbg_->Fill((char *)&ret, sizeof(T));
    return ret;
  }

 private:
  std::unique_ptr<Drbg> drbg_;
};

// Implementation of standard (cpp) and replayable UniformRandomBitGenerator
//
// see: https://en.cppreference.com/w/cpp/named_req/UniformRandomBitGenerator
//
// This implementation is provided to be used as the random bit source of
// std::shuffle. std::shuffle should internally call YaclStdUrbd with
// std::uniform_int_distribution, which again internally uses the method defined
// in A.5.1 of SP800-90A (reviewed on MacOS with libc++).
//
// NOTE this implementation is not compatiable with NIST standards as it allows
// the manipulation of internal random states.
//
template <typename T, std::enable_if_t<std::is_unsigned_v<T>, bool> = true>
class YaclReplayUrbg {
 public:
  using result_type = T;
  using CType = yacl::crypto::SymmetricCrypto::CryptoType;

  YaclReplayUrbg(uint128_t seed, uint64_t ctr, uint64_t iv = 0,
                 CType ctype = CType::AES128_CTR)
      : seed_(seed), ctr_(ctr), iv_(iv), ctype_(ctype) {}

  static constexpr T min() { return std::numeric_limits<T>::min(); }
  static constexpr T max() { return std::numeric_limits<T>::max(); }

  T operator()() {
    T ret;
    ctr_ = FillPRand(ctype_, seed_, iv_, ctr_, (char *)&ret, sizeof(T));
    return ret;
  }

  uint64_t GetSeed() const { return seed_; }
  uint64_t GetCounter() const { return ctr_; }
  uint64_t GetIV() const { return iv_; }
  CType GetCType() const { return ctype_; }

 private:
  const uint128_t seed_;
  uint64_t ctr_;  // NOTE ctr_ is mutable
  const uint64_t iv_;
  const CType ctype_;
};

template <class RandomIt>
void ReplayShuffle(RandomIt first, RandomIt last, uint128_t seed,
                   uint64_t *ctr) {
  YACL_ENFORCE(ctr != nullptr);

  using diff_t = typename std::iterator_traits<RandomIt>::difference_type;
  diff_t n = last - first;

  // prepare n-1 random numbers
  // ind[0] in [0, 1], ind[1] in [0, 2] ... ind[n-2] in [0, n-1]
  std::vector<uint128_t> ind(n - 1);

  *ctr = yacl::crypto::FillPRand(
      yacl::crypto::SymmetricCrypto::CryptoType::AES128_CTR, seed, 0, *ctr,
      (char *)ind.data(), (n - 1) * sizeof(uint128_t));

  // Though this is not strictly uniform random. it will
  // provide statistical security of no less than 40 bits.
  // i.e. for some fixed k, the statistical distance between our random
  // variables and the ground truth uniform distribution over [0, k-1] is no
  // more that 1/2 * (k / 2^{128}) < 2^{-64} (if we assume k < 2^64).
  for (int64_t idx = 0; idx < n - 1; ++idx) {
    ind[idx] = ind[idx] % (idx + 2);
  }

  // Knuth-Durstenfeld Shuffle
  for (diff_t i = n - 1; i > 0; --i) {  //
    std::swap(first[i], first[ind[i - 1]]);
  }
}

}  // namespace yacl::crypto
