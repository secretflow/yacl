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
#include <memory>
#include <vector>

#include "yacl/math/gadget.h"
#include "yacl/secparam.h"

/* submodules */
#include "yacl/kernels/algorithms/gywz_ote.h"

/* security parameter declaration */
YACL_MODULE_DECLARE("ferret_ote_rn", SecParam::C::k128, SecParam::S::INF);

namespace yacl::crypto {

inline uint64_t MpCotRNHelper(uint64_t idx_num, uint64_t idx_range) {
  const auto batch_size = idx_range / idx_num;
  const auto last_size = idx_range - batch_size * (idx_num - 1);
  return math::Log2Ceil(batch_size) * (idx_num - 1) + math::Log2Ceil(last_size);
}

inline void MpCotRNSend(const std::shared_ptr<link::Context>& ctx,
                        const OtSendStore& cot, uint64_t idx_range,
                        uint64_t idx_num, uint64_t spcot_size,
                        absl::Span<uint128_t> out) {
  const uint64_t full_size = idx_range;
  const uint64_t batch_size = spcot_size;
  const uint64_t batch_num = math::DivCeil(full_size, batch_size);
  YACL_ENFORCE(batch_num <= idx_num);

  const uint64_t last_size = full_size - (batch_num - 1) * batch_size;

  // for each bin, call single-point cot
  for (uint64_t i = 0; i < batch_num - 1; ++i) {
    const auto& cot_slice =
        cot.Slice(i * math::Log2Ceil(batch_size),
                  i * math::Log2Ceil(batch_size) + math::Log2Ceil(batch_size));
    GywzOtExtSend_ferret(ctx, cot_slice, batch_size,
                         out.subspan(i * batch_size, batch_size));
  }
  // deal with last batch
  if (last_size == 1) {
    out[(batch_num - 1) * batch_size] =
        cot.GetBlock((batch_num - 1) * math::Log2Ceil(batch_size), 0);
  } else {
    const auto& cot_slice =
        cot.Slice((batch_num - 1) * math::Log2Ceil(batch_size),
                  (batch_num - 1) * math::Log2Ceil(batch_size) +
                      math::Log2Ceil(last_size));
    GywzOtExtSend_ferret(ctx, cot_slice, last_size,
                         out.subspan((batch_num - 1) * batch_size, last_size));
  }
}

inline void MpCotRNRecv(const std::shared_ptr<link::Context>& ctx,
                        const OtRecvStore& cot, uint64_t idx_range,
                        uint64_t idx_num, uint64_t spcot_size,
                        absl::Span<uint128_t> out) {
  const uint64_t full_size = idx_range;
  const uint64_t batch_size = spcot_size;
  const uint64_t batch_num = math::DivCeil(full_size, batch_size);
  YACL_ENFORCE(batch_num <= idx_num);

  const uint64_t last_size = full_size - (batch_num - 1) * batch_size;

  // for each bin, call single-point cot
  for (uint64_t i = 0; i < batch_num - 1; ++i) {
    const auto cot_slice =
        cot.Slice(i * math::Log2Ceil(batch_size),
                  i * math::Log2Ceil(batch_size) + math::Log2Ceil(batch_size));
    GywzOtExtRecv_ferret(ctx, cot_slice, batch_size,
                         out.subspan(i * batch_size, batch_size));
  }
  // deal with last batch
  if (last_size == 1) {
    out[(batch_num - 1) * batch_size] =
        cot.GetBlock((batch_num - 1) * math::Log2Ceil(batch_size));
  } else {
    const auto& cot_slice =
        cot.Slice((batch_num - 1) * math::Log2Ceil(batch_size),
                  (batch_num - 1) * math::Log2Ceil(batch_size) +
                      math::Log2Ceil(last_size));
    GywzOtExtRecv_ferret(ctx, cot_slice, last_size,
                         out.subspan((batch_num - 1) * batch_size, last_size));
  }
}

}  // namespace yacl::crypto
