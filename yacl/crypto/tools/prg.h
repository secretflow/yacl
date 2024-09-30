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

#include <algorithm>
#include <array>
#include <cstring>
#include <memory>
#include <numeric>
#include <type_traits>
#include <vector>

#include "yacl/base/byte_container_view.h"
#include "yacl/base/dynamic_bitset.h"
#include "yacl/base/int128.h"
#include "yacl/math/mpint/mp_int.h"
#include "yacl/secparam.h"

/* submodules */
#include "yacl/crypto/block_cipher/symmetric_crypto.h"

/* security parameter declaration */
YACL_MODULE_DECLARE("prg", SecParam::C::k128, SecParam::S::k40);

namespace yacl::crypto {

// ---------------------------
//  Fill Pseudorandom (PRand)
// ---------------------------

// Core implementation of filling deterministic pseudorandomness, return the
// increased counter (count++, presumably). FillPRand-like implementations never
// perform healthcheck, reseed.
//
// NOTE FillPRand is not an instantiation of NIST800-90A.
//
uint64_t FillPRand(SymmetricCrypto::CryptoType type, uint128_t seed,
                   uint64_t iv, uint64_t count, char* buf, size_t len);

// Fill pseudo-randomness with template type T.
// Return the increased counter (count++, presumably).
template <typename T,
          std::enable_if_t<std::is_standard_layout<T>::value, int> = 0>
inline uint64_t FillPRand(SymmetricCrypto::CryptoType crypto_type,
                          uint128_t seed, uint64_t iv, uint64_t count,
                          absl::Span<T> out) {
  return FillPRand(crypto_type, seed, iv, count, (char*)out.data(),
                   out.size() * sizeof(T));
}

// -----------------------------------
//  Simpler Fill Pseudorandoms (PRand)
// -----------------------------------
// Since Prg is over-complex for simple tasks, here we provide a simple, yet
// useful way of using Prg.
template <typename T,
          std::enable_if_t<std::is_standard_layout<T>::value, int> = 0>
inline void PrgAesCtr(const uint128_t seed, absl::Span<T> out) {
  FillPRand<T>(SymmetricCrypto::CryptoType::AES128_CTR, seed, 0, 0, out);
}

template <typename T,
          std::enable_if_t<std::is_standard_layout<T>::value, int> = 0>
inline std::vector<T> PrgAesCtr(const uint128_t seed, const size_t num) {
  std::vector<T> res(num);
  FillPRand<T>(SymmetricCrypto::CryptoType::AES128_CTR, seed, 0, 0,
               absl::MakeSpan(res));
  return res;
}

template <typename T,
          std::enable_if_t<std::is_standard_layout<T>::value, int> = 0>
inline std::vector<T> PrgAesCbc(const uint128_t seed, const size_t num) {
  std::vector<T> res(num);
  FillPRand<T>(SymmetricCrypto::CryptoType::AES128_CBC, seed, 0, 0,
               absl::MakeSpan(res));
  return res;
}

// ---------------------------------------------
// Fill Pseudorandoms within MersennePrime Field
// ---------------------------------------------

// type traits for mersenne prime, currently we only support 4 types:
// uint128_t, uint64_t, uint32_t, uint8_t
template <typename T>
struct IsSupportedMersennePrimeContainerType
    : public std::disjunction<
          std::is_same<uint128_t, T>, std::is_same<uint64_t, T>,
          std::is_same<uint32_t, T>, std::is_same<uint8_t, T>> {};

template <typename T,
          std::enable_if_t<IsSupportedMersennePrimeContainerType<T>::value,
                           bool> = true>
constexpr T GetMersennePrimeMask() {
  if constexpr (std::is_same_v<T, uint128_t>) {
    return MakeUint128(std::numeric_limits<uint64_t>::max() >> 1,
                       std::numeric_limits<uint64_t>::max());
  } else if constexpr (std::is_same_v<T, uint64_t>) {
    return std::numeric_limits<uint64_t>::max() >> 3;
  } else if constexpr (std::is_same_v<T, uint32_t>) {
    return std::numeric_limits<uint32_t>::max() >> 1;
  } else if constexpr (std::is_same_v<T, uint8_t>) {
    return std::numeric_limits<uint8_t>::max() >> 1;
  } else {
    // TODO(@shanzhu): maybe throw runtime error
    YACL_THROW("Type T is not supported by FillPRandWithMersennePrime()");
  }
}

template <typename T,
          std::enable_if_t<IsSupportedMersennePrimeContainerType<T>::value,
                           bool> = true>
constexpr size_t GetMersennePrimeBitWidth() {
  if constexpr (std::is_same_v<T, uint128_t>) {
    return 127;
  } else if constexpr (std::is_same_v<T, uint64_t>) {
    return 61;
  } else if constexpr (std::is_same_v<T, uint32_t>) {
    return 31;
  } else if constexpr (std::is_same_v<T, uint8_t>) {
    return 7;
  } else {
    // TODO(@shanzhu): it's better to throw compile-time error
    YACL_THROW("Type T is not supported by FillPRandWithMersennePrime()");
  }
}

template <typename T,
          std::enable_if_t<IsSupportedMersennePrimeContainerType<T>::value,
                           bool> = true>
T MersennePrimeMod(ByteContainerView buf) {
  YACL_ENFORCE(buf.size() ==
               sizeof(T) + (YACL_MODULE_SECPARAM_S_UINT("prg") + 7) / 8);
  YACL_ENFORCE((YACL_MODULE_SECPARAM_S_UINT("prg") + 7) / 8 < sizeof(uint64_t));

  constexpr auto k_mask = GetMersennePrimeMask<T>();
  // // using mpint::mod, expensive
  // math::MPInt rand;
  // rand.FromMagBytes(buf, Endian::little);
  // return rand.Mod(math::MPInt(k_mask)).Get<T>();

  // using native methods
  // buf should have 1 * T and 1 * s
  // | --- T-len --- | --- s-len --- |
  // lsb                         msb
  //
  // int i = k % p (where p = 2^s - 1) <= what we want
  // ---------------------------------
  // int i = (k & p) + (k >> s);
  // return (i >= p) ? i - p : i;
  //

  if constexpr (std::is_same_v<T, uint128_t> || std::is_same_v<T, uint64_t>) {
    T rand = 0;
    uint64_t aux_rand = 0;
    memcpy(&rand, buf.data(), sizeof(T));
    memcpy(&aux_rand, buf.data() + sizeof(T),
           (YACL_MODULE_SECPARAM_S_UINT("prg") + 7) / 8);

    // single round would work
    T i = (rand & k_mask) + aux_rand;
    return (i > k_mask) ? i - k_mask : i;
  } else {
    YACL_ENFORCE(buf.size() <= sizeof(uint128_t));
    uint128_t all_rand = 0;
    memcpy(&all_rand, buf.data(), buf.size());

    // constant round
    do {
      uint128_t i = (all_rand & k_mask) /* < 31 bit */ +
                    (all_rand >> GetMersennePrimeBitWidth<T>()) /* 40 bit */;
      all_rand = (i >= k_mask) ? i - k_mask : i;
    } while (all_rand >= k_mask);
    return (T)all_rand;
  }
}

template <typename T,
          std::enable_if_t<IsSupportedMersennePrimeContainerType<T>::value,
                           bool> = true>
uint64_t FillPRandWithMersennePrime(SymmetricCrypto::CryptoType crypto_type,
                                    uint128_t seed, uint64_t iv, uint64_t count,
                                    absl::Span<T> out) {
  if constexpr (std::is_same_v<T, uint128_t> || std::is_same_v<T, uint64_t>) {
    // first, fill all outputs with randomness
    auto ret = FillPRand(crypto_type, seed, iv, count, (char*)out.data(),
                         out.size() * sizeof(T));

    // then, perform fast mod (in a non-standardized way)
    // NOTE: for mersenne prime with 127, 61 bit width, it's sufficient to
    // sample 127/61 bit uniform randomness directly, and then let the 2^127
    // value to be zero. Though this is not strictly uniform random, it will
    // provide statistical security of no less than 40 bits.
    constexpr auto k_mask = GetMersennePrimeMask<T>();
    for (auto& e : out) {
      e = (e & k_mask) == k_mask ? 0 : e & k_mask;
    }
    return ret;
  } else {
    // first, fill all outputs with randomness
    auto required_size =
        sizeof(T) + (YACL_MODULE_SECPARAM_S_UINT("prg") + 7) / 8;
    Buffer rand_bytes(out.size() * required_size);
    auto ret = FillPRand(crypto_type, seed, iv, count, (char*)rand_bytes.data(),
                         out.size() * required_size);

    // then, perform mod
    ByteContainerView rand_view(rand_bytes);
    for (size_t i = 0; i < out.size(); ++i) {
      out[i] = MersennePrimeMod<T>(
          rand_view.subspan(i * required_size, required_size));
    }
    return ret;
  }
}

// -----------------------------
// Fill Pseudorandoms within mod
// -----------------------------

// type traits, currently we only support 3 types:
// uint128_t, uint64_t, uint32_t
template <typename T>
struct IsSupportedLtNContainerType
    : public std::disjunction<std::is_same<uint128_t, T>,
                              std::is_same<uint64_t, T>,
                              std::is_same<uint32_t, T>> {};

template <typename T,
          std::enable_if_t<IsSupportedLtNContainerType<T>::value, bool> = true>
uint64_t FillPRandWithLtN(SymmetricCrypto::CryptoType crypto_type,
                          uint128_t seed, uint64_t iv, uint64_t count,
                          absl::Span<T> out, T n) {
  size_t n_bit_width = 0;
  // first, fill all outputs with randomness
  if constexpr (std::is_same_v<T, uint128_t>) {
    n_bit_width = CountBitWidth(n);
  } else {
    n_bit_width = absl::bit_width(n);
  }

  auto required_size =
      (n_bit_width + YACL_MODULE_SECPARAM_S_UINT("prg") + 7) / 8;
  Buffer rand_bytes(out.size() * required_size);
  auto ret = FillPRand(crypto_type, seed, iv, count, (char*)rand_bytes.data(),
                       out.size() * required_size);

  // then, perform mod
  ByteContainerView rand_view(rand_bytes);
  for (size_t i = 0; i < out.size(); ++i) {
    math::MPInt r;
    r.FromMagBytes(rand_view.subspan(i * required_size, required_size),
                   Endian::little);
    math::MPInt::Mod(r, math::MPInt(n), &r);
    out[i] = r.Get<T>();
  }
  return ret;
}

// ---------------------------
//       PRG with cache
// ---------------------------

namespace internal {
template <typename T, size_t BATCH_SIZE>
struct cipher_data {
  std::array<T, BATCH_SIZE> cipher_budget_{};

  size_t size() { return BATCH_SIZE * sizeof(T); }
  T& operator[](size_t idx) { return cipher_budget_[idx]; }
  const T& operator[](size_t idx) const { return cipher_budget_[idx]; }
};

template <size_t BATCH_SIZE>
struct cipher_data<bool, BATCH_SIZE> {
  dynamic_bitset<uint128_t> cipher_budget_;

  cipher_data() { cipher_budget_ = dynamic_bitset<uint128_t>(BATCH_SIZE * 8); }
  size_t size() { return BATCH_SIZE; }

  bool operator[](const size_t& idx) { return cipher_budget_[idx]; }
  bool operator[](const size_t& idx) const { return cipher_budget_[idx]; }
};
}  // namespace internal

// core implementation of prg
enum class PRG_MODE {
  kAesEcb,  // aes-128 ecb (with an internal counter)
  kSm4Ecb,  // sm4-128 ecb (with an internal counter)
};

template <typename T, size_t BATCH_SIZE = 16,
          std::enable_if_t<std::is_standard_layout_v<T>, int> = 0>
class Prg {
 public:
  static_assert(BATCH_SIZE * sizeof(T) % sizeof(uint128_t) == 0);

  // constructor
  explicit Prg(uint128_t seed = 0, PRG_MODE mode = PRG_MODE::kAesEcb)
      : mode_(mode) {
    SetSeed(seed);
  }

  uint128_t Seed() const { return seed_; }
  uint128_t Counter() const { return counter_; }

  static constexpr size_t BatchSize() { return BATCH_SIZE; }

  void SetSeed(uint128_t seed) {
    seed_ = seed;
    counter_ = 0;  // Reset counter. Make this behave same with STL PRG.
  }

  void SetStatus(uint128_t seed, uint128_t counter) {
    seed_ = seed;
    counter_ = counter;
  }

  T operator()() {
    if (num_consumed_ == cipher_data_.cipher_budget_.size()) {
      GenerateBudgets();  // Generate budgets.
      num_consumed_ = 0;  // Reset consumed.
    }
    return cipher_data_[num_consumed_++];
  }

  // `Fill` does not consumes cipher_budgets but do increase the internal
  // counter.
  template <typename Y,
            std::enable_if_t<std::is_trivially_copyable_v<Y>, int> = 0>
  void Fill(absl::Span<Y> out) {
    switch (mode_) {
      case PRG_MODE::kAesEcb:
        counter_ = FillPRand(
            SymmetricCrypto::CryptoType::AES128_ECB, seed_, kInitVector,
            counter_,
            absl::Span<uint8_t>((uint8_t*)out.data(), sizeof(Y) * out.size()));
        break;
      case PRG_MODE::kSm4Ecb:
        counter_ = FillPRand(
            SymmetricCrypto::CryptoType::SM4_ECB, seed_, kInitVector, counter_,
            absl::Span<uint8_t>((uint8_t*)out.data(), sizeof(Y) * out.size()));
        break;
    }
  }

  inline static constexpr uint128_t kInitVector = 0;

 private:
  void GenerateBudgets() {
    auto* cipher_ptr =
        reinterpret_cast<uint8_t*>(cipher_data_.cipher_budget_.data());
    size_t cipher_size = cipher_data_.size();

    switch (mode_) {
      case PRG_MODE::kAesEcb:
        counter_ = FillPRand(SymmetricCrypto::CryptoType::AES128_ECB, seed_,
                             kInitVector, counter_,
                             absl::MakeSpan(cipher_ptr, cipher_size));
        break;
      case PRG_MODE::kSm4Ecb:
        counter_ =
            FillPRand(SymmetricCrypto::CryptoType::SM4_ECB, seed_, kInitVector,
                      counter_, absl::MakeSpan(cipher_ptr, cipher_size));
        break;
    }
  }

  uint128_t seed_;                                    // Seed.
  uint128_t counter_ = 0;                             // Counter.
  internal::cipher_data<T, BATCH_SIZE> cipher_data_;  // budget (in bytes).
  size_t num_consumed_ = BATCH_SIZE;  // How many ciphers are consumed.

  PRG_MODE mode_;  // prg mode
};

}  // namespace yacl::crypto
