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

#include "yacl/crypto/primitives/ot/ferret_ote.h"

#include <fmt/core.h>

#include <algorithm>
#include <memory>
#include <utility>
#include <vector>

#include "yacl/base/exception.h"
#include "yacl/crypto/primitives/ot/gywz_ote.h"
#include "yacl/crypto/primitives/ot/ot_store.h"
#include "yacl/crypto/primitives/ot/sgrr_ote.h"
#include "yacl/crypto/tools/linear_code.h"
#include "yacl/crypto/tools/random_permutation.h"
#include "yacl/utils/serialize.h"

namespace yacl::crypto {

namespace {

// default cuckoo parameters, for details see yacl/utils/cuckoo_index.h
constexpr uint64_t kCuckooStashNum = 0;      // cuckoo parameter: stash
constexpr uint64_t kCuckooHashNim = 3;       // cuckoo parameter: hash number
constexpr uint64_t kStatSecurityParam = 40;  // statstical sec param

constexpr auto kFerretRpType = SymmetricCrypto::CryptoType::AES128_ECB;
// FIXME: use different seed on each invocation
constexpr auto kFerretRpSeed = 0x12345678;

const auto RP = RandomPerm(kFerretRpType, kFerretRpSeed);  // for cuckoo

uint128_t GenSyncedSeed(const std::shared_ptr<link::Context>& ctx) {
  YACL_ENFORCE(ctx->WorldSize() == 2);
  uint128_t seed;

  if (ctx->Rank() == 0) {
    seed = SecureRandSeed();
    ctx->SendAsync(ctx->NextRank(), SerializeUint128(seed), "SEND:Seed");
  } else {
    seed = DeserializeUint128(ctx->Recv(ctx->NextRank(), "RECV:Seed"));
  }
  return seed;
}

std::unique_ptr<FerretSimpleMap> MakeSimpleMap(
    const CuckooIndex::Options& options, uint64_t n) {
  const auto bin_num = options.NumBins();

  auto out = std::make_unique<FerretSimpleMap>(bin_num);

  // get index set {0, 1, ..., n}, and then RP
  std::vector<uint128_t> idx_blocks(n);
  std::iota(idx_blocks.begin(), idx_blocks.end(), 0);

  // random permutation
  auto idxes_h = RP.Gen(idx_blocks);

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

void MpCotSendImpl_AnyIndices(const std::shared_ptr<link::Context>& ctx,
                              const OtSendStore& cot, const MpCotOption& option,
                              absl::Span<uint128_t> out) {
  YACL_ENFORCE(option.use_cuckoo);

  const auto& simple_map = option.simple_map;
  const uint64_t bin_num = option.cuckoo_option.NumBins();

  // for each bin, call single-point c-ot
  std::vector<std::vector<uint128_t>> s(bin_num);

  uint64_t slice_begin = 0;
  for (uint64_t i = 0; i < bin_num && !simple_map->operator[](i).empty(); ++i) {
    // run single-point cot for this bin, with out size =
    // simple_table_size + 1
    const uint64_t spcot_range_n = simple_map->operator[](i).size() + 1;
    const auto spot_option = MakeSpCotOption(spcot_range_n);

    s[i].resize(spcot_range_n);
    auto cot_slice =
        cot.Slice(slice_begin, slice_begin + Log2Ceil(spcot_range_n));
    SpCotSend(ctx, cot_slice, spot_option, absl::MakeSpan(s[i]));
    slice_begin += Log2Ceil(spcot_range_n);
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

void MpCotRecvImpl_AnyIndices(const std::shared_ptr<link::Context>& ctx,
                              const OtRecvStore& cot, const MpCotOption& option,
                              absl::Span<const uint64_t> idxes,
                              absl::Span<uint128_t> out) {
  YACL_ENFORCE(option.use_cuckoo);

  const auto& simple_map = option.simple_map;
  const uint64_t bin_num = option.cuckoo_option.NumBins();

  // random permutation
  std::vector<uint128_t> idx_blocks(idxes.begin(), idxes.end());
  auto idxes_h = RP.Gen(idx_blocks);

  CuckooIndex cuckoo_index(option.cuckoo_option);
  cuckoo_index.Insert(absl::MakeSpan(idxes_h));

  // for each (non-empty) cuckoo bin, call single-point c-ot
  std::fill(out.begin(), out.end(), 0);
  std::vector<std::vector<uint128_t>> r(bin_num);

  uint64_t slice_begin = 0;
  for (uint64_t i = 0; i < bin_num && !simple_map->operator[](i).empty(); ++i) {
    // if cuckoo bin is empty, we use idx = simple_table_size
    const uint64_t spcot_range_n = simple_map->operator[](i).size() + 1;
    const auto spot_option = MakeSpCotOption(spcot_range_n);

    uint64_t spcot_idx = spcot_range_n - 1;
    if (!cuckoo_index.bins()[i].IsEmpty()) {  // if bin is not empty
      spcot_idx =
          simple_map->operator[](i)[idxes[cuckoo_index.bins()[i].InputIdx()]];
    }

    r[i].resize(spcot_range_n);

    auto cot_slice =
        cot.Slice(slice_begin, slice_begin + Log2Ceil(spcot_range_n));
    SpCotRecv(ctx, cot_slice, spot_option, spcot_idx, absl::MakeSpan(r[i]));
    slice_begin += Log2Ceil(spcot_range_n);
  }

  // calculate the final result for each (non-empty) bin
  for (uint64_t i = 0; i < bin_num && !simple_map->operator[](i).empty(); ++i) {
    for (auto const& x : simple_map->operator[](i)) {
      out[x.first] ^= r[i][x.second];
    }
  }
}

void MpCotSendImpl_RegularIndices(const std::shared_ptr<link::Context>& ctx,
                                  const OtSendStore& cot,
                                  const MpCotOption& option,
                                  absl::Span<uint128_t> out) {
  YACL_ENFORCE(!option.use_cuckoo);

  const auto full_size = option.idx_range;
  const auto batch_num = option.idx_num;
  const auto batch_size = (full_size + batch_num - 1) / batch_num;

  // for each bin, call single-point cot
  for (uint64_t i = 0; i < batch_num; ++i) {
    const uint64_t limit = std::min(batch_size, full_size - i * batch_size);
    const auto& cot_slice =
        cot.Slice(i * Log2Ceil(limit), (i + 1) * Log2Ceil(limit));
    SpCotSend(ctx, cot_slice, MakeSpCotOption(limit),
              out.subspan(i * batch_size, limit));
  }
}

void MpCotRecvImpl_RegularIndices(const std::shared_ptr<link::Context>& ctx,
                                  const OtRecvStore& cot,
                                  const MpCotOption& option,
                                  absl::Span<const uint64_t> idxes,
                                  absl::Span<uint128_t> out) {
  YACL_ENFORCE(!option.use_cuckoo);

  const auto full_size = option.idx_range;
  const auto batch_num = option.idx_num;
  const auto batch_size = (full_size + batch_num - 1) / batch_num;

  // for each bin, call single-point cot
  for (uint64_t i = 0; i < batch_num; ++i) {
    const uint64_t limit = std::min(batch_size, full_size - i * batch_size);
    const auto cot_slice =
        cot.Slice(i * Log2Ceil(limit), (i + 1) * Log2Ceil(limit));
    const auto batch_idx = idxes[i] - i * batch_size;
    SpCotRecv(ctx, cot_slice, MakeSpCotOption(limit), batch_idx,
              out.subspan(i * batch_size, limit));
  }
}

}  // namespace

FerretOtExtOption MakeFerretOtExtOption(const LpnParam& lpn_param,
                                        uint64_t ot_num) {
  auto use_cuckoo = lpn_param.noise_asm == LpnNoiseAsm::UniformNoise;

  // make simple_map if required
  auto mpcot_option = MakeMpCotOption(lpn_param.t, lpn_param.n, use_cuckoo);

  // The required cots are used as:
  // (1) expansion seed: kFerret_lpnK
  // (2) mpcot cot: mp_option.cot_num (just for the first batch)
  uint64_t cot_num = lpn_param.k + mpcot_option.cot_num;

  return {lpn_param, cot_num, std::move(mpcot_option)};
}

std::shared_ptr<OtSendStore> FerretOtExtSend(
    const std::shared_ptr<link::Context>& ctx, const OtSendStore& base_cot,
    const FerretOtExtOption& option, uint64_t ot_num) {
  YACL_ENFORCE(ctx->WorldSize() == 2);  // Make sure that OT has two parties
  YACL_ENFORCE(base_cot.Size() >= option.cot_num);
  YACL_ENFORCE(base_cot.Type() == OtStoreType::Compact);

  // get batch information
  const uint64_t cache_size = option.lpn_param.k + option.mpcot_option.cot_num;
  const uint64_t batch_size = option.lpn_param.n - cache_size;
  const uint64_t batch_num = (ot_num + batch_size - 1) / batch_size;
  const uint128_t delta = base_cot.GetDelta();

  // prepare v (before silent expansion), where w = v ^ u * delta
  auto cot_seed = base_cot.Slice(0, option.lpn_param.k);
  auto cot_mpcot = base_cot.Slice(
      option.lpn_param.k, option.lpn_param.k + option.mpcot_option.cot_num);
  auto working_v = cot_seed.CopyCotBlocks();

  // get lpn public matrix A
  uint128_t seed = GenSyncedSeed(ctx);
  LocalLinearCode<10> llc(seed, option.lpn_param.n, option.lpn_param.k);

  std::vector<uint128_t> msg;
  msg.reserve(batch_num * batch_size + cache_size);
  msg.resize(batch_num * batch_size + cache_size);
  auto msg_span = absl::MakeSpan(msg.data(), msg.size());

  for (uint64_t i = 0; i < batch_num; ++i) {
    // run mpcot (get s)
    auto working_s = msg_span.subspan(i * batch_size, option.lpn_param.n);
    MpCotSend(ctx, cot_mpcot, option.mpcot_option, working_s);

    // use lpn to calculate v*A
    // llc.Encode(in,out) would calculate out = out + in * A
    llc.Encode(working_v, working_s);

    bool is_last_batch = (i == batch_num - 1);
    // update v (first lpn_k of va^s)
    if (!is_last_batch) {
      // update v for the next batch
      for (uint64_t j = 0; j < option.lpn_param.k; ++j) {
        // const auto tmp = va[j] ^ s[j];
        const auto tmp = working_s[batch_size + j];
        if ((tmp & 0x1) == 0) {
          working_v[j] = tmp;
        } else {
          working_v[j] = tmp ^ delta;
        }
      }

      // manually set the cot for next batch mpcot
      cot_mpcot.ResetSlice();
      for (uint64_t j = 0; j < option.mpcot_option.cot_num; ++j) {
        // const auto tmp = va[j + option.lpn_param.k] ^ s[j +
        // option.lpn_param.k];
        const auto tmp = working_s[batch_size + option.lpn_param.k + j];
        if ((tmp & 0x1) == 0) {
          cot_mpcot.SetCompactBlock(j, tmp);
        } else {
          cot_mpcot.SetCompactBlock(j, tmp ^ delta);
        }
      }
    }

    // result y = vA ^ s (the resting lpn_n - lpn_k)
    const uint64_t limit = std::min(batch_size, ot_num - i * batch_size);

    for (uint64_t j = 0; j < limit; ++j) {
      if ((working_s[j] & 0x1) == 1) {
        working_s[j] ^= delta;
      }
    }
  }

  msg.resize(ot_num);
  auto ot_store = MakeCompactOtSendStore(std::move(msg), delta);
  return std::make_shared<OtSendStore>(ot_store);
}

std::shared_ptr<OtRecvStore> FerretOtExtRecv(
    const std::shared_ptr<link::Context>& ctx, const OtRecvStore& base_cot,
    const FerretOtExtOption& option, uint64_t ot_num) {
  YACL_ENFORCE(ctx->WorldSize() == 2);  // Make sure that OT has two parties
  YACL_ENFORCE(base_cot.Size() >= option.cot_num);
  YACL_ENFORCE(base_cot.Type() == OtStoreType::Compact);

  const uint64_t cache_size = option.lpn_param.k + option.mpcot_option.cot_num;
  const uint64_t batch_size = option.lpn_param.n - cache_size;
  const uint64_t batch_num = (ot_num + batch_size - 1) / batch_size;

  // F2, but we store it in uint128_t
  std::vector<uint128_t> u(option.lpn_param.k);

  // prepare u, w, where w = v ^ u * delta
  auto cot_seed = base_cot.Slice(0, option.lpn_param.k);
  auto cot_mpcot = base_cot.Slice(
      option.lpn_param.k, option.lpn_param.k + option.mpcot_option.cot_num);

  auto working_w = cot_seed.CopyBlocks();

  // get lpn public matrix A
  uint128_t seed = GenSyncedSeed(ctx);
  LocalLinearCode<10> llc(seed, option.lpn_param.n, option.lpn_param.k);

  std::vector<uint128_t> msg;
  msg.reserve(batch_num * batch_size + cache_size);
  msg.resize(batch_num * batch_size + cache_size);

  auto msg_span = absl::MakeSpan(msg);

  for (uint64_t i = 0; i < batch_num; ++i) {
    // get e
    auto e = MakeRegularRandChoices(option.lpn_param.t, option.lpn_param.n);

    // run mpcot (get r)
    auto working_r = msg_span.subspan(i * batch_size, option.lpn_param.n);
    MpCotRecv(ctx, cot_mpcot, option.mpcot_option, e, working_r);

    // use lpn to calculate w*A, and u*A
    // llc.Encode(in,out) would calculate out = out + in * A
    llc.Encode(working_w, working_r);

    bool is_last_batch = (i == batch_num - 1);
    if (!is_last_batch) {
      // update u, w (first lpn_k of va^s)
      for (uint64_t j = 0; j < option.lpn_param.k; ++j) {
        working_w[j] = working_r[batch_size + j];
      }

      // manually set the cot for next batch mpcot
      cot_mpcot.ResetSlice();
      for (uint64_t j = 0; j < option.mpcot_option.cot_num; ++j) {
        cot_mpcot.SetBlock(j, working_r[batch_size + j + option.lpn_param.k]);
      }
    }
  }

  msg.resize(ot_num);
  auto ot_store = MakeCompactOtRecvStore(std::move(msg));
  return std::make_shared<OtRecvStore>(ot_store);
}

MpCotOption MakeMpCotOption(uint64_t idx_num, uint64_t idx_range,
                            bool use_cuckoo) {
  MpCotOption out;
  out.use_cuckoo = use_cuckoo;
  out.idx_num = idx_num;
  out.idx_range = idx_range;
  out.cot_num = 0;

  if (use_cuckoo) {
    out.cuckoo_option = CuckooIndex::SelectParams(
        idx_num, kCuckooStashNum, kCuckooHashNim, kStatSecurityParam);
    out.simple_map = MakeSimpleMap(out.cuckoo_option, idx_range);
    for (const auto& bin : *out.simple_map) {
      if (bin.empty()) {  // if simple table bin empty, skip
        continue;
      }
      out.cot_num += Log2Ceil(bin.size() + 1);  // each bin need an extra
    }
  } else {
    // if range = 5, idx_num = 2, we want 2 bins
    // bin[0] = 0, 1, 2
    // bin[1] = 3, 4
    const auto batch_size = (idx_range + idx_num - 1) / idx_num;
    const auto last_size = idx_range - batch_size * (idx_num - 1);
    out.cot_num = Log2Ceil(batch_size) * (idx_num - 1) + Log2Ceil(last_size);
  }
  return out;
}

void MpCotSend(const std::shared_ptr<link::Context>& ctx,
               const OtSendStore& cot, const MpCotOption& option,
               absl::Span<uint128_t> out) {
  YACL_ENFORCE_GE(cot.Size(), option.cot_num);
  YACL_ENFORCE_EQ(out.size(), option.idx_range);

  if (option.use_cuckoo) {
    MpCotSendImpl_AnyIndices(ctx, cot, option, out);
  } else {
    MpCotSendImpl_RegularIndices(ctx, cot, option, out);
  }
}

void MpCotRecv(const std::shared_ptr<link::Context>& ctx,
               const OtRecvStore& cot, const MpCotOption& option,
               absl::Span<const uint64_t> idxes, absl::Span<uint128_t> out) {
  YACL_ENFORCE(idxes.size() > 1);
  YACL_ENFORCE_GE(cot.Size(), option.cot_num);
  YACL_ENFORCE_EQ(idxes.size(), option.idx_num);
  YACL_ENFORCE_EQ(out.size(), option.idx_range);

  if (option.use_cuckoo) {
    MpCotRecvImpl_AnyIndices(ctx, cot, option, idxes, out);
  } else {
    MpCotRecvImpl_RegularIndices(ctx, cot, option, idxes, out);
  }
}

void SpCotSend(const std::shared_ptr<link::Context>& ctx,
               const OtSendStore& base_cot, const SpCotOption& option,
               absl::Span<uint128_t> out) {
  YACL_ENFORCE_GE(base_cot.Size(), option.cot_num);
  YACL_ENFORCE_EQ(out.size(), option.idx_range);

  GywzOtExtSend(ctx, base_cot, option.idx_range, out);
}

void SpCotRecv(const std::shared_ptr<link::Context>& ctx,
               const OtRecvStore& cot, const SpCotOption& option, uint64_t idx,
               absl::Span<uint128_t> out) {
  YACL_ENFORCE_GE(cot.Size(), option.cot_num);
  YACL_ENFORCE_EQ(out.size(), option.idx_range);
  YACL_ENFORCE_GT(option.idx_range, idx);

  GywzOtExtRecv(ctx, cot, option.idx_range, idx, out);
}

}  // namespace yacl::crypto
