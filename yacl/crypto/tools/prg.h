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

#include <array>
#include <cstring>
#include <memory>
#include <numeric>
#include <vector>

#include "yacl/base/dynamic_bitset.h"
#include "yacl/base/int128.h"
#include "yacl/secparam.h"

/* submodules */
#include "yacl/crypto/block_cipher/symmetric_crypto.h"

/* security parameter declaration */
YACL_MODULE_DECLARE("prg", SecParam::C::k128, SecParam::S::INF);

namespace yacl::crypto {

// ---------------------------
//  Fill Pseudorandom (PRand)
// ---------------------------

// Core implementation of filling deterministic pseudorandomness, return the
// increased counter (count++, presumably).
// Note: FillPRand is different from drbg, NIST800-90A since FillPRand will
// never perform healthcheck, reseed. FillPRand is only an abstract API for the
// theoretical tool: PRG.
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
