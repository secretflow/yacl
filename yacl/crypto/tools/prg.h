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
#include <numeric>

#include "yacl/base/int128.h"
#include "yacl/crypto/base/drbg/drbg.h"
#include "yacl/crypto/base/drbg/entropy_source.h"
#include "yacl/crypto/base/drbg/nist_aes_drbg.h"
#include "yacl/crypto/base/drbg/sm4_drbg.h"
#include "yacl/crypto/base/symmetric_crypto.h"

namespace yacl {

// define PRG mode
enum class PRG_MODE {
  // get random seed from intel entropy source, generate pseudorandom bytes
  kNistAesCtrDrbg,  // nist drbg standard
  kGmSm4CtrDrbg,    // gm  drbg
  // get seed from parameter, use ctr mode, generate pseudorandom bytes
  kAesEcb,  // use aes128
  KSm4Ecb   // use sm4
};

namespace internal {
template <typename T, size_t BATCH_SIZE>
struct cipher_data {
  std::array<T, BATCH_SIZE> cipher_budget_{};
  T& operator[](size_t idx) { return cipher_budget_[idx]; }
  const T& operator[](size_t idx) const { return cipher_budget_[idx]; }
};

// TODO: `bool` memory usage is not ideal. Figure out a better way.
template <size_t BATCH_SIZE>
struct cipher_data<bool, BATCH_SIZE> {
  std::array<std::uint8_t, BATCH_SIZE> cipher_budget_{};
  bool operator[](const size_t& idx) { return !!(cipher_budget_[idx] & 0x01); }
  bool operator[](const size_t& idx) const {
    return !!(cipher_budget_[idx] & 0x01);
  }
};
}  // namespace internal

template <typename T, size_t BATCH_SIZE = 128,
          std::enable_if_t<std::is_standard_layout_v<T>, int> = 0>
class Prg {
 public:
  static_assert(BATCH_SIZE % sizeof(uint128_t) == 0);

  explicit Prg(uint128_t seed = 0, PRG_MODE prg_mode = PRG_MODE::kAesEcb)
      : prg_mode_(prg_mode) {
    SetSeed(seed);

    if (prg_mode_ == PRG_MODE::kNistAesCtrDrbg) {
      ctr_drbg_ = std::make_unique<yacl::crypto::NistAesDrbg>(seed);
    } else if (prg_mode_ == PRG_MODE::kGmSm4CtrDrbg) {
      ctr_drbg_ = std::make_unique<yacl::crypto::Sm4Drbg>(seed);
    }
  }

  uint128_t Seed() const { return seed_; }

  uint128_t Counter() const { return counter_; }

  static constexpr size_t BatchSize() { return BATCH_SIZE; }

  void SetSeed(uint128_t seed) {
    seed_ = seed;
    // Reset counter. Make this behave same with STL PRG.
    counter_ = 0;
  }

  void SetStatus(uint128_t seed, uint128_t counter) {
    seed_ = seed;
    counter_ = counter;
  }

  T operator()() {
    if (num_consumed_ == cipher_data_.cipher_budget_.size()) {
      // Generate budgets.
      GenerateBudgets();
      // Reset consumed.
      num_consumed_ = 0;
    }
    return cipher_data_[num_consumed_++];
  }

  template <typename Y,
            std::enable_if_t<std::is_trivially_copyable_v<Y>, int> = 0>
  void Fill(absl::Span<Y> out) {
    // `Fill` does not consumes cipher_budgets but do increase the internal
    // counter.
    switch (prg_mode_) {
      case PRG_MODE::kNistAesCtrDrbg:
      case PRG_MODE::kGmSm4CtrDrbg:
        ctr_drbg_->FillRandom(absl::MakeSpan(out));
        break;
      case PRG_MODE::kAesEcb:
        counter_ = FillPseudoRandom(SymmetricCrypto::CryptoType::AES128_ECB,
                                    seed_, kInitVector, counter_, out);
        break;
      case PRG_MODE::KSm4Ecb:
        counter_ = FillPseudoRandom(SymmetricCrypto::CryptoType::SM4_ECB, seed_,
                                    kInitVector, counter_, out);
        break;
    }
  }

  inline static constexpr uint128_t kInitVector = 0;

 private:
  void GenerateBudgets() {
    switch (prg_mode_) {
      case PRG_MODE::kNistAesCtrDrbg:
      case PRG_MODE::kGmSm4CtrDrbg:
        ctr_drbg_->FillRandom(absl::MakeSpan(cipher_data_.cipher_budget_));
        break;
      case PRG_MODE::kAesEcb:
        counter_ = FillPseudoRandom(
            SymmetricCrypto::CryptoType::AES128_ECB, seed_, kInitVector,
            counter_, absl::MakeSpan(cipher_data_.cipher_budget_));
        break;
      case PRG_MODE::KSm4Ecb:
        counter_ = FillPseudoRandom(
            SymmetricCrypto::CryptoType::SM4_ECB, seed_, kInitVector, counter_,
            absl::MakeSpan(cipher_data_.cipher_budget_));
        break;
    }
  }

  // Seed.
  uint128_t seed_;
  // Counter as encrypt messages.
  uint128_t counter_ = 0;
  // Cipher budget.
  internal::cipher_data<T, BATCH_SIZE> cipher_data_;
  // How many ciphers are consumed.
  size_t num_consumed_ = BATCH_SIZE;

  PRG_MODE prg_mode_;
  // for nist aes ctr drbg
  std::unique_ptr<yacl::crypto::IDrbg> ctr_drbg_;
};

}  // namespace yacl
