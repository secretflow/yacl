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

#include "yacl/base/exception.h"
#include "yacl/base/int128.h"
#include "yacl/math/f2k/f2k_utils.h"
#include "yacl/math/gadget.h"

/* submodules */
#include "yacl/kernel/algorithms/ot_store.h"
#include "yacl/kernel/algorithms/softspoken_ote.h"
#include "yacl/secparam.h"

YACL_MODULE_DECLARE("base_vole", SecParam::C::INF, SecParam::S::INF);
namespace yacl::crypto {

// Convert OT to f2k-VOLE (non-interactive)
// the type of ot_store must be COT
// w = u * delta + v, where delta = send_ot.delta
// notice:
//  - non-interactive method, which means that Ot2Vole could achieve malicious
//  secure if send_ot/recv_ot are malicious secure.
// usage:
//  - Vole:  u in GF(2^64); w, v, delta in GF(2^64)
// Ot2VoleSend<uint64_t,uint64_t> / Ot2VoleRecv<uint64_t,uint64_t>
//  - Vole:  u in GF(2^128); w, v, delta in GF(2^128)
// Ot2VoleSend<uint128_t,uint128_t> / Ot2VoleRecv<uint128_t,uint128_t>
//  - subfield Vole: u in GF(2^64); w, v, delta in GF(2^128)
// Ot2VoleSend<uint64_t,uint128_t> / Ot2VoleRecv<uint64_t,uint128_t>
template <typename T, typename K>
void inline Ot2VoleSend(OtSendStore& send_ot, absl::Span<K> w) {
  constexpr size_t T_bits = sizeof(T) * 8;
  const uint64_t size = w.size();

  YACL_ENFORCE(send_ot.Size() >= size * T_bits);

  std::array<K, T_bits> w_buff;
  std::array<K, T_bits> basis;
  if (std::is_same<K, uint128_t>::value) {
    memcpy(basis.data(), gf128_basis.data(), T_bits * sizeof(K));
  } else if (std::is_same<K, uint64_t>::value) {
    memcpy(basis.data(), gf64_basis.data(), T_bits * sizeof(K));
  } else {
    YACL_THROW("VoleSend Error!");
  }

  for (uint64_t i = 0; i < size; ++i) {
    // [Warning] Copying, low efficiency
    for (size_t j = 0; j < T_bits; ++j) {
      w_buff[j] = send_ot.GetBlock(i * T_bits + j, 0);
    }
    w[i] = math::GfMul(absl::MakeSpan(w_buff), absl::MakeSpan(basis));
  }
}

template <typename T, typename K>
void inline Ot2VoleRecv(OtRecvStore& recv_ot, absl::Span<T> u,
                        absl::Span<K> v) {
  constexpr size_t T_bits = sizeof(T) * 8;
  const uint64_t size = u.size();
  YACL_ENFORCE(u.size() == v.size());
  YACL_ENFORCE(recv_ot.Size() >= size * T_bits);

  // [Warning] Copying, low efficiency
  auto choices = recv_ot.CopyChoice();
  memcpy(u.data(), choices.data(), size * sizeof(T));

  std::array<K, T_bits> v_buff;
  std::array<K, T_bits> basis;
  if (std::is_same<K, uint128_t>::value) {
    memcpy(basis.data(), gf128_basis.data(), T_bits * sizeof(K));
  } else if (std::is_same<K, uint64_t>::value) {
    memcpy(basis.data(), gf64_basis.data(), T_bits * sizeof(K));
  } else {
    YACL_THROW("VoleSend Error!");
  }

  for (uint64_t i = 0; i < size; ++i) {
    // [Warning] Copying, low efficiency
    for (size_t j = 0; j < T_bits; ++j) {
      v_buff[j] = recv_ot.GetBlock(i * T_bits + j);
    }
    v[i] = math::GfMul(absl::MakeSpan(v_buff), absl::MakeSpan(basis));
  }
}

// Generate f2k-VOLE by Gilboa Method
// the type of ot_store must be Base-OT (ROT)
// w = u * delta + v, where delta = base_ot.choices
// usage:
//  - Vole:  u in GF(2^64); w, v, delta in GF(2^64)
// GilboaVoleSend<uint64_t,uint64_t> / GilboaVoleRecv<uint64_t,uint64_t>
//  - Vole:  u in GF(2^128); w, v, delta in GF(2^128)
// GilboaVoleSend<uint128_t,uint128_t> / GilboaVoleRecv<uint128_t,uint128_t>
//  - subfield Vole: u in GF(2^64); w, v, delta in GF(2^128)
// GilboaVoleSend<uint64_t,uint128_t> / GilboaVoleRecv<uint64_t,uint128_t>
template <typename T, typename K>
void inline GilboaVoleSend(const std::shared_ptr<link::Context>& ctx,
                           const OtRecvStore& base_ot, absl::Span<K> w,
                           bool mal = false) {
  constexpr size_t T_bits = sizeof(T) * 8;
  const size_t size = w.size();

  auto sender = SoftspokenOtExtSender(2, mal);
  // setup Softspoken by base_ot
  sender.OneTimeSetup(ctx, base_ot);
  auto send_ot = sender.GenCot(ctx, size * T_bits);
  Ot2VoleSend<T, K>(send_ot, w);
}

template <typename T, typename K>
void inline GilboaVoleRecv(const std::shared_ptr<link::Context>& ctx,
                           const OtSendStore& base_ot, absl::Span<T> u,
                           absl::Span<K> v, bool mal = false) {
  constexpr size_t T_bits = sizeof(T) * 8;
  const size_t size = u.size();
  YACL_ENFORCE(size == v.size());

  auto receiver = SoftspokenOtExtReceiver(2, mal);
  // setup Softspoken by base_ot
  receiver.OneTimeSetup(ctx, base_ot);
  auto recv_ot = receiver.GenCot(ctx, size * T_bits);
  Ot2VoleRecv<T, K>(recv_ot, u, v);
}

}  // namespace yacl::crypto
