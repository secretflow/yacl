// Copyright 2023 Ant Group Co., Ltd.
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

#include <functional>
#include <vector>

/* submodules */
#include "yacl/crypto/rand/rand.h"
#include "yacl/kernel/algorithms/ot_store.h"
#include "yacl/secparam.h"

/* security parameter declaration */
// this module is only a wrapper, no need for security parameter definition

namespace yacl::crypto {

// 2PC Multi-point functional secret sharing (MPFSS) implementation
//
// (n,t)-MPFSS is described in https://eprint.iacr.org/2019/273.pdf Section 4.
// In short, Sender and Receiver would input t-index (idx_1 , ... , idx_t) and
// t-element (val_1 , ... , val_t) respectively, and then get an output with
// n-element (output_1 , ... , output_n), such that:
//  - for all k not in (idx_1 , ... , idx_t), Sender.output[k] =
//  Receiver.output[k]
//  - When k = idx_i, then Sender.output[k] = Receiver.output[k] + val_i
//
// Besides, in reference https://eprint.iacr.org/2019/1159.pdf Section 4,
// punctured PRF could be viewed as 2PC DPF.
//

struct MpFssParam {
  uint64_t base_vole_num_;
  uint64_t noise_num_;
  uint64_t sp_vole_size_;
  uint64_t last_sp_vole_size_;
  // mp_vole_size_ = sp_vole_size_ * (noise_num_ - 1) + last_sp_vole_size_
  uint64_t mp_vole_size_;    // total size
  uint64_t require_ot_num_;  // total ot num

  LpnNoiseAsm assumption_ = LpnNoiseAsm::RegularNoise;
  std::vector<uint32_t> indexes_ = std::vector<uint32_t>(0);  // size zero

  bool is_mal_{false};

  MpFssParam() : MpFssParam(1, 2, LpnNoiseAsm::RegularNoise, false) {}

  MpFssParam(uint64_t noise_num, uint64_t mp_vole_size, bool mal = false)
      : MpFssParam(noise_num, mp_vole_size, LpnNoiseAsm::RegularNoise, mal) {}

  // full constructor
  MpFssParam(uint64_t noise_num, uint64_t mp_vole_size, LpnNoiseAsm assumption,
             bool mal = false) {
    YACL_ENFORCE(assumption == LpnNoiseAsm::RegularNoise);
    YACL_ENFORCE(noise_num > 0);

    is_mal_ = mal;
    base_vole_num_ = (is_mal_ == false) ? noise_num : noise_num + 1;
    noise_num_ = noise_num;
    mp_vole_size_ = mp_vole_size;
    assumption_ = assumption;

    sp_vole_size_ = mp_vole_size_ / noise_num_;
    last_sp_vole_size_ = mp_vole_size_ - (noise_num_ - 1) * sp_vole_size_;

    YACL_ENFORCE(sp_vole_size_ > 1,
                 "The size of SpVole should be greater than 1, because "
                 "1-out-of-1 SpVole is meaningless");

    require_ot_num_ = math::Log2Ceil(sp_vole_size_) * (noise_num_ - 1) +
                      math::Log2Ceil(last_sp_vole_size_);
  }

  // [Warning] not strictly uniformly random
  void GenIndexes() {
    indexes_ = RandVec<uint32_t>(noise_num_);
    for (uint32_t i = 0; i < noise_num_ - 1; ++i) {
      indexes_[i] %= sp_vole_size_;
    }
    indexes_[noise_num_ - 1] %= last_sp_vole_size_;
  }

  void SetIndexes(absl::Span<const uint32_t> indexes) {
    YACL_ENFORCE(indexes.size() >= noise_num_);
    for (uint32_t i = 0; i < noise_num_ - 1; ++i) {
      indexes_[i] = indexes[i] % sp_vole_size_;
    }
    indexes_[noise_num_ - 1] %= last_sp_vole_size_;
  }

  // Convert index_ into choices for OT
  dynamic_bitset<uint128_t> GenChoices() {
    YACL_ENFORCE(indexes_.size() == noise_num_);

    auto choices = dynamic_bitset<uint128_t>(require_ot_num_);

    uint64_t pos = 0;
    auto sp_vole_length = math::Log2Ceil(sp_vole_size_);
    auto last_length = math::Log2Ceil(last_sp_vole_size_);
    for (size_t i = 0; i < noise_num_; ++i) {
      auto this_length = (i == noise_num_ - 1) ? last_length : sp_vole_length;
      uint32_t bound = 1 << this_length;
      for (uint32_t mask = 1; mask < bound; mask <<= 1) {
        choices.set(pos, indexes_[i] & mask);
        ++pos;
      }
    }

    return choices;
  }
};

template <typename T>
class MpfssOp {
 public:
  std::function<T(const T&, const T&)> add = std::bit_xor<T>();
  std::function<T(const T&, const T&)> sub = std::bit_xor<T>();

  // Maybe, we could define a function to convert uint128_t to T
  //  - std::function<T(uint128_t)> convert = static_cast<T>();
  //  - std::function<T(uint128_t)> convert = PRF<T>();

  // default ctor
  MpfssOp() {
    add = std::bit_xor<T>();
    sub = std::bit_xor<T>();
  }

  // standard ctor
  MpfssOp(std::function<T(const T&, const T&)> op1,
          std::function<T(const T&, const T&)> op2) {
    add = op1;
    sub = op2;
  }
};

template <typename T>
MpfssOp<T> MakeMpfssOp(std::function<T(const T&, const T&)> op1,
                       std::function<T(const T&, const T&)> op2) {
  return MpfssOp<T>(op1, op2);
}

// Multi-point functional secret share with Regular Noise Distribution (GYWZ-OTe
// based) [Warning] low efficiency, too much send action

// GF(2^128) or Ring(2^128)
void MpfssSend(const std::shared_ptr<link::Context>& ctx,
               const OtSendStore& /*cot*/ send_ot, const MpFssParam& param,
               absl::Span<const uint128_t> w, absl::Span<uint128_t> output,
               const MpfssOp<uint128_t>& op = MpfssOp<uint128_t>());

void MpfssRecv(const std::shared_ptr<link::Context>& ctx,
               const OtRecvStore& /*cot*/ recv_ot, const MpFssParam& param,
               absl::Span<uint128_t> output,
               const MpfssOp<uint128_t>& op = MpfssOp<uint128_t>());

// GF(2^64) or Ring(2^64)
void MpfssSend(const std::shared_ptr<link::Context>& ctx,
               const OtSendStore& /*cot*/ send_ot, const MpFssParam& param,
               absl::Span<const uint64_t> w, absl::Span<uint64_t> output,
               const MpfssOp<uint64_t>& op = MpfssOp<uint64_t>());

void MpfssRecv(const std::shared_ptr<link::Context>& ctx,
               const OtRecvStore& /*cot*/ recv_ot, const MpFssParam& param,
               absl::Span<uint64_t> output,
               const MpfssOp<uint64_t>& op = MpfssOp<uint64_t>());
//
// --------------------------
//         Customized
// --------------------------
//
// Multi-point functional secret share with Regular Noise Distribution (GYWZ-OTe
// based) Most efficiency! Punctured indexes would be determined by the choices
// of OtStore. But "MpfssSend_fixed_index/MpfssRecv_fixed_index" would not check
// whether the indexes determined by OtStore and the indexes provided by
// MpFssParam are same.

// GF(2^128) or Ring(2^128)
void MpfssSend_fixed_index(const std::shared_ptr<link::Context>& ctx,
                           const OtSendStore& /*cot*/ send_ot,
                           MpFssParam& param, absl::Span<const uint128_t> w,
                           absl::Span<uint128_t> output,
                           const MpfssOp<uint128_t>& op = MpfssOp<uint128_t>());

void MpfssRecv_fixed_index(const std::shared_ptr<link::Context>& ctx,
                           const OtRecvStore& /*cot*/ recv_ot,
                           MpFssParam& param, absl::Span<uint128_t> output,
                           const MpfssOp<uint128_t>& op = MpfssOp<uint128_t>());

// GF(2^64) or Ring(2^64)
void MpfssSend_fixed_index(const std::shared_ptr<link::Context>& ctx,
                           const OtSendStore& /*cot*/ send_ot,
                           MpFssParam& param, absl::Span<const uint64_t> w,
                           absl::Span<uint64_t> output,
                           const MpfssOp<uint64_t>& op = MpfssOp<uint64_t>());

void MpfssRecv_fixed_index(const std::shared_ptr<link::Context>& ctx,
                           const OtRecvStore& /*cot*/ recv_ot,
                           MpFssParam& param, absl::Span<uint64_t> output,
                           const MpfssOp<uint64_t>& op = MpfssOp<uint64_t>());

}  // namespace yacl::crypto
