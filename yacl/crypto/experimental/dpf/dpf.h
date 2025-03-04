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
#include <cstdint>
#include <iostream>
#include <random>
#include <string>
#include <thread>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

#include "yacl/base/exception.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/experimental/dpf/ge2n.h"

/* submodules */
#include "yacl/crypto/rand/rand.h"
#include "yacl/crypto/tools/prg.h"
#include "yacl/secparam.h"

YACL_MODULE_DECLARE("dpf", SecParam::C::k128, SecParam::S::INF);

namespace yacl::crypto {

// Distributed Point Function (DPF)
//
// For more details, please see: https://eprint.iacr.org/2018/707
//
class DpfKey {
 public:
  // internal type definition
  class CW {
   public:
    CW() = default;
    CW(uint128_t seed, uint8_t t_store) : seed_(seed), t_store_(t_store) {}

    uint8_t GetLT() const { return t_store_ & 1; }
    uint8_t GetRT() const { return (t_store_ >> 1) & 1; }

    uint128_t GetSeed() const { return seed_; }
    uint8_t GetTStore() const { return t_store_; }

    void SetLT(uint8_t t_left) {
      YACL_ENFORCE(t_left == 0 || t_left == 1);
      t_store_ = (GetRT() << 1) + t_left;
    }

    void SetRT(uint8_t t_right) {
      YACL_ENFORCE(t_right == 0 || t_right == 1);
      t_store_ = (t_right << 1) + GetLT();
    }

    void SetSeed(uint128_t seed) { seed_ = seed; }

   private:
    uint128_t seed_ = 0;   // this level's seed, default = 0
    uint8_t t_store_ = 0;  // 1st bit=> t_left, 2nd bit=> t_right
  };

  bool enable_evalall = false;         // full domain eval
  std::vector<CW> cws_vec;             // correlated words for each level
  std::vector<uint128_t> last_cw_vec;  // the final correlation word

  // empty constructor
  DpfKey() = default;

  explicit DpfKey(bool rank, const uint128_t mseed = SecureRandSeed())
      : rank_(rank), mseed_(mseed) {}

  void EnableEvalAll() { enable_evalall = true; }
  void DisableFullEval() { enable_evalall = false; }

  bool GetRank() const { return rank_; }
  void SetRank(bool rank) { rank_ = rank; }

  uint128_t GetSeed() const { return mseed_; }
  void SetSeed(uint128_t seed) { mseed_ = seed; }

 private:
  bool rank_{};          // only support two parties (0/1), compulsory param
  uint128_t mseed_ = 0;  // the master seed
};

// ----------------------------------------------------------------------------
// Core Functions of DPF
// ----------------------------------------------------------------------------
// NOTE: Supported (M, N) parameter pairs are:
// - (M = {8, 16, 32, 64}, N = {8, 16, 32, 64, 128})
//
// TODO maybe type traits
// template <size_t M, size_t N>
// struct IsSupportedDpfType {
//   static constexpr std::array<size_t, 4> m_set = {8, 16, 32, 64};
//   static constexpr std::array<size_t, 5> n_set = {8, 16, 32, 64, 128};
//   static constexpr bool value = []() constexpr {
//     return std::find(std::begin(m_set), std::end(m_set), M) !=
//                std::end(m_set) &&
//            std::find(std::begin(n_set), std::end(m_set), N) !=
//            std::end(n_set);
//     ;
//   };
// };

template <size_t /* input bit num */ M, size_t /* output bit num */ N>
void DpfKeyGen(DpfKey* first_key, DpfKey* second_key, const GE2n<M>& alpha,
               const GE2n<N>& beta, uint128_t first_mk, uint128_t second_mk,
               bool enable_evalall = false);

template <size_t /* input bit num */ M, size_t /* output bit num */ N>
void DpfEval(const DpfKey& key, const GE2n<M>& in, GE2n<N>* out);

template <size_t /* input bit num */ M, size_t /* output bit num */ N>
void DpfEvalAll(DpfKey* key, absl::Span<GE2n<N>> out);

}  // namespace yacl::crypto
