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

#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/crypto/tools/common.h"
#include "yacl/math/f2k/f2k_utils.h"
#include "yacl/secparam.h"

/* submodules */
#include "yacl/kernel/algorithms/gywz_ote.h"

/* security parameter declaration */
YACL_MODULE_DECLARE("ferret_ote_rn", SecParam::C::k128, SecParam::S::INF);

namespace yacl::crypto {

inline uint64_t MpCotRNHelper(uint64_t idx_num, uint64_t idx_range,
                              bool mal = false) {
  const auto batch_size = (idx_range + idx_num - 1) / idx_num;
  const auto last_size = idx_range - batch_size * (idx_num - 1);
  const auto check_size = (mal == true) ? 128 : 0;
  return math::Log2Ceil(batch_size) * (idx_num - 1) +
         math::Log2Ceil(last_size) + check_size;
}

inline void MpCotRNSend(const std::shared_ptr<link::Context>& ctx,
                        const OtSendStore& cot, uint64_t idx_range,
                        uint64_t idx_num, uint64_t spcot_size,
                        absl::Span<uint128_t> out, bool mal = false) {
  const uint64_t full_size = idx_range;
  const uint64_t batch_size = spcot_size;
  const uint64_t batch_num = math::DivCeil(full_size, batch_size);
  YACL_ENFORCE(batch_num <= idx_num);

  const uint64_t last_size = full_size - (batch_num - 1) * batch_size;
  const uint64_t batch_length = math::Log2Ceil(batch_size);
  const uint64_t last_length = math::Log2Ceil(last_size);

  // for each bin, call single-point cot
  for (uint64_t i = 0; i < batch_num - 1; ++i) {
    const auto& cot_slice =
        cot.Slice(i * batch_length, i * batch_length + batch_length);
    GywzOtExtSend_ferret(ctx, cot_slice, batch_size,
                         out.subspan(i * batch_size, batch_size));
  }
  // deal with last batch
  if (last_size == 1) {
    out[(batch_num - 1) * batch_size] =
        cot.GetBlock((batch_num - 1) * batch_length, 0);
  } else {
    const auto& cot_slice =
        cot.Slice((batch_num - 1) * batch_length,
                  (batch_num - 1) * batch_length + last_length);
    GywzOtExtSend_ferret(ctx, cot_slice, last_size,
                         out.subspan((batch_num - 1) * batch_size, last_size));
  }

  if (mal) {
    // COT for Consistency check
    auto check_cot =
        cot.Slice(batch_length * (batch_num - 1) + last_length,
                  batch_length * (batch_num - 1) + last_length + 128);

    auto seed = SyncSeedSend(ctx);
    auto uhash = math::UniversalHash<uint128_t>(seed, out);

    auto recv_buf = ctx->Recv(ctx->NextRank(), "FerretCheck: masked choices");
    auto choices = dynamic_bitset<uint128_t>(0);
    choices.append(DeserializeUint128(recv_buf));

    std::array<uint128_t, 128> check_cot_data;
    for (size_t i = 0; i < 128; ++i) {
      check_cot_data[i] = check_cot.GetBlock(i, choices[i]);
    }
    auto diff = PackGf128(absl::MakeSpan(check_cot_data));
    uhash = uhash ^ diff;

    auto hash = Blake3(SerializeUint128(uhash));
    ctx->SendAsync(ctx->NextRank(), ByteContainerView(hash),
                   "FerretCheck: hash value");
  }
}

inline void MpCotRNRecv(const std::shared_ptr<link::Context>& ctx,
                        const OtRecvStore& cot, uint64_t idx_range,
                        uint64_t idx_num, uint64_t spcot_size,
                        absl::Span<uint128_t> out, bool mal = false) {
  const uint64_t full_size = idx_range;
  const uint64_t batch_size = spcot_size;
  const uint64_t batch_num = math::DivCeil(full_size, batch_size);
  YACL_ENFORCE(batch_num <= idx_num);

  const uint64_t last_size = full_size - (batch_num - 1) * batch_size;
  const uint64_t batch_length = math::Log2Ceil(batch_size);
  const uint64_t last_length = math::Log2Ceil(last_size);

  // for each bin, call single-point cot
  for (uint64_t i = 0; i < batch_num - 1; ++i) {
    const auto cot_slice =
        cot.Slice(i * batch_length, i * batch_length + batch_length);
    GywzOtExtRecv_ferret(ctx, cot_slice, batch_size,
                         out.subspan(i * batch_size, batch_size));
  }
  // deal with last batch
  if (last_size == 1) {
    out[(batch_num - 1) * batch_size] =
        cot.GetBlock((batch_num - 1) * batch_length);
  } else {
    const auto& cot_slice =
        cot.Slice((batch_num - 1) * batch_length,
                  (batch_num - 1) * batch_length + last_length);
    GywzOtExtRecv_ferret(ctx, cot_slice, last_size,
                         out.subspan((batch_num - 1) * batch_size, last_size));
  }
  // malicious: consistency check
  if (mal) {
    // COT for consistency check
    auto check_cot =
        cot.Slice(batch_length * (batch_num - 1) + last_length,
                  batch_length * (batch_num - 1) + last_length + 128);
    auto seed = SyncSeedRecv(ctx);
    auto uhash = math::UniversalHash<uint128_t>(seed, out);

    // [Warning] low efficency
    uint128_t choices = check_cot.CopyChoice().data()[0];

    auto check_cot_data = check_cot.CopyBlocks();
    auto diff = PackGf128(absl::MakeSpan(check_cot_data));
    uhash = uhash ^ diff;

    // find punctured indexes
    std::vector<uint64_t> indexes;
    for (size_t i = 0; i < out.size(); ++i) {
      if (out[i] & 0x1) {
        indexes.push_back(i);
      }
    }
    // extract the coefficent for universal hash
    auto ceof = math::ExtractHashCoef(seed, absl::MakeConstSpan(indexes));
    choices = std::accumulate(ceof.cbegin(), ceof.cend(), choices,
                              std::bit_xor<uint128_t>());

    ctx->SendAsync(ctx->NextRank(), SerializeUint128(choices),
                   "FerretCheck: masked choices");

    auto hash = Blake3(SerializeUint128(uhash));
    auto buf = ctx->Recv(ctx->NextRank(), "FerretCheck: hash value");

    YACL_ENFORCE(ByteContainerView(hash) == ByteContainerView(buf),
                 "FerretCheck: fail");
  }
}

}  // namespace yacl::crypto
