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
#include <unordered_map>
#include <vector>

#include "yacl/math/gadget.h"
#include "yacl/secparam.h"
#include "yacl/utils/cuckoo_index.h"

/* submodules */
#include "yacl/crypto/tools/rp.h"
#include "yacl/kernel/algorithms/gywz_ote.h"

/* security parameter declaration */
YACL_MODULE_DECLARE("ferret_ote_un", SecParam::C::k128, SecParam::S::INF);

namespace yacl::crypto {

using FerretSimpleMap = std::vector<std::unordered_map<uint64_t, uint64_t>>;

constexpr auto kFerretRpType = SymmetricCrypto::CryptoType::AES128_ECB;
constexpr auto kFerretRpSeed = 0x12345678;  // FIXME: use different seeds
constexpr auto kFerretCuckooHashNum = 3;
constexpr auto kFerretCuckooStashNum = 0;
const auto kRP = RP(kFerretRpType, kFerretRpSeed);  // for cuckoo

// create simple map
inline std::unique_ptr<FerretSimpleMap> MakeSimpleMap(
    const CuckooIndex::Options& options, uint64_t n) {
  const auto bin_num = options.NumBins();

  auto out = std::make_unique<FerretSimpleMap>(bin_num);

  // get index set {0, 1, ..., n}, and then RP
  UninitAlignedVector<uint128_t> idx_blocks(n);
  std::iota(idx_blocks.begin(), idx_blocks.end(), 0);

  // random permutation
  auto idxes_h = kRP.Gen(idx_blocks);

  // for each index (value), calculate its cuckoo bin_idx
  for (uint64_t i = 0; i < n; ++i) {
    CuckooIndex::HashRoom itemHash(idxes_h[i]);

    // Note the handling of possible index collision should be same as how we
    // operate in `yacl/utils/cuckoo_index.cc` (use the min colliding index)
    uint64_t bin_idx0 = itemHash.GetHash(0) % bin_num;
    out->operator[](bin_idx0).insert({i, out->operator[](bin_idx0).size()});

    uint64_t bin_idx1 = itemHash.GetHash(1) % bin_num;
    if (bin_idx1 != bin_idx0) {  // if no collision happens
      out->operator[](bin_idx1).insert({i, out->operator[](bin_idx1).size()});
    }

    uint64_t bin_idx2 = itemHash.GetHash(2) % bin_num;
    if (bin_idx2 != bin_idx0 &&  // if no collision happens
        bin_idx2 != bin_idx1) {  // if no collision happens
      out->operator[](bin_idx2).insert({i, out->operator[](bin_idx2).size()});
    }
  }

  return out;
}

// Multi-Point Correlated OT ("length") Extension Implementation
//
// This implementation bases on Ferret, for more theoretical details, see
// https://eprint.iacr.org/2020/924.pdf, section 4, figure 7.
//
//              +---------+    +------------+
//              |   COT   | => |   MP-COT   |
//              +---------+    +------------+
//              num = n           num = t
//              len = kappa       len = 2^n
//
//  > kappa: computation security parameter (128 for example)
//
// Threat Model:
//  > Passive Adversary
//
// Security assumptions:
//  > SpCotSend / SpCotRecv (see previous codes in this file)

inline uint64_t MpCotUNHelper(uint64_t idx_num, uint64_t idx_range) {
  auto option = CuckooIndex::SelectParams(idx_num, kFerretCuckooStashNum,
                                          kFerretCuckooHashNum);
  // [note] this is larger than the actual required cot num
  return math::Log2Ceil(idx_range) * option.NumBins();
}

inline void MpCotUNSend(const std::shared_ptr<link::Context>& ctx,
                        const OtSendStore& cot,
                        const std::unique_ptr<FerretSimpleMap>& simple_map,
                        const CuckooIndex::Options& cuckoo_option,
                        absl::Span<uint128_t> out) {
  const uint64_t bin_num = cuckoo_option.NumBins();

  // for each bin, call single-point cot
  UninitAlignedVector<UninitAlignedVector<uint128_t>> s(bin_num);

  uint64_t slice_begin = 0;
  for (uint64_t i = 0; i < bin_num && !simple_map->operator[](i).empty(); ++i) {
    // run single-point cot for this bin, with out size =
    // simple_table_size + 1
    const uint64_t spcot_range_n = simple_map->operator[](i).size() + 1;
    const auto spot_option = math::Log2Ceil(spcot_range_n);

    s[i].resize(spcot_range_n);
    auto cot_slice = cot.Slice(slice_begin, slice_begin + spot_option);
    GywzOtExtSend(ctx, cot_slice, spcot_range_n, absl::MakeSpan(s[i]));
    slice_begin += spot_option;
  }

  // calculate the final result for each bin
  std::fill(out.begin(), out.end(), 0);
  for (uint64_t i = 0; i < bin_num; ++i) {
    if (simple_map->operator[](i).empty()) {  // if simple table bin empty, skip
      continue;
    }
    for (auto const& x : simple_map->operator[](i)) {
      out[x.first] ^= s[i][x.second];
    }
  }
}

inline void MpCotUNRecv(const std::shared_ptr<link::Context>& ctx,
                        const OtRecvStore& cot,
                        const std::unique_ptr<FerretSimpleMap>& simple_map,
                        const CuckooIndex::Options& cuckoo_option,
                        absl::Span<const uint64_t> idxes,
                        absl::Span<uint128_t> out) {
  const uint64_t bin_num = cuckoo_option.NumBins();

  // random permutation
  UninitAlignedVector<uint128_t> idx_blocks(idxes.begin(), idxes.end());
  auto idxes_h = kRP.Gen(idx_blocks);

  CuckooIndex cuckoo_index(cuckoo_option);
  cuckoo_index.Insert(absl::MakeSpan(idxes_h));

  // for each (non-empty) cuckoo bin, call single-point c-ot
  std::fill(out.begin(), out.end(), 0);
  UninitAlignedVector<UninitAlignedVector<uint128_t>> r(bin_num);

  uint64_t slice_begin = 0;
  for (uint64_t i = 0; i < bin_num && !simple_map->operator[](i).empty(); ++i) {
    // if cuckoo bin is empty, we use idx = simple_table_size
    const uint64_t spcot_range_n = simple_map->operator[](i).size() + 1;
    const auto spot_option = math::Log2Ceil(spcot_range_n);

    uint64_t spcot_idx = spcot_range_n - 1;
    if (!cuckoo_index.bins()[i].IsEmpty()) {  // if bin is not empty
      spcot_idx = simple_map->operator[](i).at(
          idxes[cuckoo_index.bins()[i].InputIdx()]);
    }

    r[i].resize(spcot_range_n);

    auto cot_slice = cot.Slice(slice_begin, slice_begin + spot_option);
    GywzOtExtRecv(ctx, cot_slice, spcot_range_n, spcot_idx,
                  absl::MakeSpan(r[i]));
    slice_begin += spot_option;
  }

  // calculate the final result for each (non-empty) bin
  for (uint64_t i = 0; i < bin_num && !simple_map->operator[](i).empty(); ++i) {
    for (auto const& x : simple_map->operator[](i)) {
      out[x.first] ^= r[i][x.second];
    }
  }
}

}  // namespace yacl::crypto
