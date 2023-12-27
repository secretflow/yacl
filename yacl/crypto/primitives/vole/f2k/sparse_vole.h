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

#include "yacl/crypto/primitives/ot/ot_store.h"
#include "yacl/crypto/utils/secparam.h"
#include "yacl/math/gadget.h"

/* submodules */
#include "yacl/crypto/primitives/ot/ferret_ote.h"
#include "yacl/crypto/primitives/ot/gywz_ote.h"
#include "yacl/crypto/primitives/ot/sgrr_ote.h"
#include "yacl/crypto/primitives/ot/softspoken_ote.h"
#include "yacl/crypto/tools/crhash.h"
#include "yacl/crypto/tools/rp.h"
#include "yacl/crypto/utils/rand.h"

/* security parameter declaration */
YACL_MODULE_DECLARE("sparse_vole", SecParam::C::INF, SecParam::S::INF);

namespace yacl::crypto {

// Implementation about sparse-VOLE over GF(2^128), including base-VOLE,
// single-point VOLE and multi-point VOLE. For more detail, see
// https://eprint.iacr.org/2019/1084.pdf protocol 4 & protocol 5.

// Single-point f2k-Vole (by SGRR-OTe)
// the type of ot_store must be ROT
// void SpVoleSend(const std::shared_ptr<link::Context>& ctx,
//                 const OtSendStore& /*rot*/ send_ot, uint32_t n, uint128_t w,
//                 absl::Span<uint128_t> output);

// void SpVoleRecv(const std::shared_ptr<link::Context>& ctx,
//                 const OtRecvStore& /*rot*/ recv_ot, uint32_t n, uint32_t
//                 index, uint128_t v, absl::Span<uint128_t> output);

// Single-point GF(2^128)-Vole (by GYWZ-OTe)
// the type of ot_store must be COT
void SpVoleSend(const std::shared_ptr<link::Context>& ctx,
                const OtSendStore& /*cot*/ send_ot, uint32_t n, uint128_t w,
                absl::Span<uint128_t> output);

void SpVoleRecv(const std::shared_ptr<link::Context>& ctx,
                const OtRecvStore& /*cot*/ recv_ot, uint32_t n, uint32_t index,
                uint128_t v, absl::Span<uint128_t> output);

struct MpVoleParam {
  uint64_t noise_num_;
  uint64_t sp_vole_size_;
  uint64_t last_sp_vole_size_;

  uint64_t mp_vole_size_;
  uint64_t require_ot_num_;  // total ot num

  std::vector<uint32_t> indexes_;
  LpnNoiseAsm assumption_;

  MpVoleParam() : MpVoleParam(1, 2) {}

  MpVoleParam(uint64_t noise_num, uint64_t mp_vole_size,
              LpnNoiseAsm assumption = LpnNoiseAsm::RegularNoise) {
    YACL_ENFORCE(assumption == LpnNoiseAsm::RegularNoise);
    YACL_ENFORCE(noise_num > 0);
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
    for (uint32_t i = 0; i < noise_num_ - 1; ++i) {
      indexes_[i] = indexes[i] % sp_vole_size_;
    }
    indexes_[noise_num_ - 1] %= last_sp_vole_size_;
  }
};

// Multi-point f2k-Vole with Regular Noise (SGRR-OTe based)
// void MpVoleSend(const std::shared_ptr<link::Context>& ctx,
//                 const OtSendStore& /*rot*/ send_ot, const MpVoleParam& param,
//                 absl::Span<uint128_t> w, absl::Span<uint128_t> output);

// void MpVoleRecv(const std::shared_ptr<link::Context>& ctx,
//                 const OtRecvStore& /*rot*/ recv_ot, const MpVoleParam& param,
//                 absl::Span<uint128_t> v, absl::Span<uint128_t> output);

// Multi-point GF(2^128)-Vole with Regular Noise (GYWZ-OTe based)
void MpVoleSend(const std::shared_ptr<link::Context>& ctx,
                const OtSendStore& /*cot*/ send_ot, const MpVoleParam& param,
                absl::Span<const uint128_t> w, absl::Span<uint128_t> output);

void MpVoleRecv(const std::shared_ptr<link::Context>& ctx,
                const OtRecvStore& /*cot*/ recv_ot, const MpVoleParam& param,
                absl::Span<const uint128_t> v, absl::Span<uint128_t> output);

//
// --------------------------
//         Customized
// --------------------------
//
// Multi-point f2k-Vole with Regular Noise (GYWZ-OTe based)
// Most efficiency! Punctured indexes would be determined by the choices of
// OtStore. But "MpVoleSend_fixed_index/MpVoleRecv_fixed_index" would not check
// whether the indexes determined by OtStore and the indexes provided by
// MpVoleParam are same.、
//
// GF(2^128)
void MpVoleSend_fixed_index(const std::shared_ptr<link::Context>& ctx,
                            const OtSendStore& /*cot*/ send_ot,
                            const MpVoleParam& param,
                            absl::Span<const uint128_t> w,
                            absl::Span<uint128_t> output);

void MpVoleRecv_fixed_index(const std::shared_ptr<link::Context>& ctx,
                            const OtRecvStore& /*cot*/ recv_ot,
                            const MpVoleParam& param,
                            absl::Span<const uint128_t> v,
                            absl::Span<uint128_t> output);

// GF(2^64)
void MpVoleSend_fixed_index(const std::shared_ptr<link::Context>& ctx,
                            const OtSendStore& /*cot*/ send_ot,
                            const MpVoleParam& param,
                            absl::Span<const uint64_t> w,
                            absl::Span<uint64_t> output);

void MpVoleRecv_fixed_index(const std::shared_ptr<link::Context>& ctx,
                            const OtRecvStore& /*cot*/ recv_ot,
                            const MpVoleParam& param,
                            absl::Span<const uint64_t> v,
                            absl::Span<uint64_t> output);

}  // namespace yacl::crypto
