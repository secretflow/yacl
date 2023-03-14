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

#include <algorithm>

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

std::shared_ptr<FerretSimpleMap> MakeSimpleMap(
    const CuckooIndex::Options& options, uint64_t n) {
  const auto bin_num = options.NumBins();

  auto out = std::make_shared<FerretSimpleMap>(bin_num);

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
                              const std::shared_ptr<OtSendStore>& cot,
                              const MpCotOption& option,
                              absl::Span<uint128_t> out) {
  YACL_ENFORCE(option.use_cuckoo);
  const auto& simple_map = option.simple_map;
  const uint64_t bin_num = option.cuckoo_option.NumBins();

  // for each bin, call single-point c-ot
  std::vector<std::vector<uint128_t>> s(bin_num);

  for (uint64_t i = 0; i < bin_num && !simple_map->operator[](i).empty(); ++i) {
    // run single-point cot for this bin, with out size =
    // simple_table_size + 1
    const uint64_t spcot_range_n = simple_map->operator[](i).size() + 1;
    const auto spot_option = MakeSpCotOption(spcot_range_n);

    s[i].resize(spcot_range_n);
    auto cot_slice = cot->NextSlice(Log2Ceil(spcot_range_n));
    SpCotSend(ctx, cot_slice, spot_option, absl::MakeSpan(s[i]));
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
                              const std::shared_ptr<OtRecvStore>& cot,
                              const MpCotOption& option,
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

    auto cot_slice = cot->NextSlice(Log2Ceil(spcot_range_n));
    SpCotRecv(ctx, cot_slice, spot_option, spcot_idx, absl::MakeSpan(r[i]));
  }

  // calculate the final result for each (non-empty) bin
  for (uint64_t i = 0; i < bin_num && !simple_map->operator[](i).empty(); ++i) {
    for (auto const& x : simple_map->operator[](i)) {
      out[x.first] ^= r[i][x.second];
    }
  }
}

void MpCotSendImpl_RegularIndices(const std::shared_ptr<link::Context>& ctx,
                                  const std::shared_ptr<OtSendStore>& cot,
                                  const MpCotOption& option,
                                  absl::Span<uint128_t> out) {
  YACL_ENFORCE(!option.use_cuckoo);

  const auto full_size = option.idx_range;
  const auto batch_num = option.idx_num;
  const auto batch_size = (full_size + batch_num - 1) / batch_num;

  // for each bin, call single-point cot
  for (uint64_t i = 0; i < batch_num; ++i) {
    const uint64_t limit = std::min(batch_size, full_size - i * batch_size);
    const auto& cot_slice = cot->NextSlice(Log2Ceil(limit));

    SpCotSend(ctx, cot_slice, MakeSpCotOption(limit),
              out.subspan(i * batch_size, limit));
  }
}

void MpCotRecvImpl_RegularIndices(const std::shared_ptr<link::Context>& ctx,
                                  const std::shared_ptr<OtRecvStore>& cot,
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
    const auto cot_slice = cot->NextSlice(Log2Ceil(limit));
    const auto batch_idx = idxes[i] - i * batch_size;

    SpCotRecv(ctx, cot_slice, MakeSpCotOption(limit), batch_idx,
              out.subspan(i * batch_size, limit));
  }
}

}  // namespace

FerretOtExtOption MakeFerretOtExtOption(uint64_t output_ot_num, bool use_cuckoo,
                                        uint64_t lpn_n, uint64_t lpn_k,
                                        uint64_t lpn_t) {
  auto mpcot_option = MakeMpCotOption(lpn_t, lpn_n, use_cuckoo);

  const uint64_t batch_size = lpn_n - lpn_k;
  const uint64_t batch_num = (output_ot_num + batch_size - 1) / batch_size;

  // The required cots are used as:
  // (1) expansion seed: kFerret_lpnK
  // (2) mpcot cot: mp_option.cot_num (per batch)
  uint64_t cot_num = lpn_k + mpcot_option.cot_num * batch_num;

  return {lpn_n, lpn_k, lpn_t, cot_num, use_cuckoo, mpcot_option};
}

std::shared_ptr<OtSendStore> FerretOtExtSend(
    const std::shared_ptr<link::Context>& ctx,
    const std::shared_ptr<OtSendStore>& base_cot,
    const FerretOtExtOption& option, uint64_t ot_num) {
  YACL_ENFORCE(ctx->WorldSize() == 2);  // Make sure that OT has two parties
  YACL_ENFORCE_GE(base_cot->Size(), option.lpn_k);
  YACL_ENFORCE(base_cot->IsCompactCot());  // base ot should be compact

  auto ot_store = std::make_shared<OtSendStore>(ot_num, true);  // compact mode
  const uint128_t delta = base_cot->GetDelta();
  ot_store->SetDelta(delta);

  const uint64_t batch_size = option.lpn_n - option.lpn_k;
  const uint64_t batch_num = (ot_num + batch_size - 1) / batch_size;

  // prepare v (before silent expansion), where w = v ^ u * delta
  auto cot_seed = base_cot->NextSlice(option.lpn_k);
  auto working_v = cot_seed->CopyCotBlocks();

  // get lpn public matrix A
  uint128_t seed = GenSyncedSeed(ctx);
  LocalLinearCode<10> llc(seed, option.lpn_n, option.lpn_k);

  for (uint64_t i = 0; i < batch_num; ++i) {
    bool is_last_batch = (i == batch_num - 1);

    // run mpcot (get s)
    std::vector<uint128_t> s(option.lpn_n);
    auto cot_batch = base_cot->NextSlice(option.mpcot_option.cot_num);
    MpCotSend(ctx, cot_batch, option.mpcot_option, absl::MakeSpan(s));

    // use lpn to calculate v*A
    std::vector<uint128_t> va(option.lpn_n);
    llc.Encode(working_v, absl::MakeSpan(va));

    // update v (first lpn_k of va^s)
    if (!is_last_batch) {
      // update v for the next batch
      for (uint64_t j = 0; j < option.lpn_k; ++j) {
        const auto tmp = va[j] ^ s[j];
        if ((tmp & 0x1) == 0) {
          working_v[j] = tmp;
        } else {
          working_v[j] = tmp ^ delta;
        }
      }
    }

    // result y = vA ^ s (the resting lpn_n - lpn_k)
    const uint64_t limit = std::min(batch_size, ot_num - i * batch_size);

    for (uint64_t j = 0; j < limit; ++j) {
      const auto tmp = va[j + option.lpn_k] ^ s[j + option.lpn_k];
      if ((tmp & 0x1) == 0) {
        ot_store->SetCompactBlock(i * batch_size + j, tmp);
      } else {
        ot_store->SetCompactBlock(i * batch_size + j, tmp ^ delta);
      }
    }
  }
  return ot_store;
}

std::shared_ptr<OtRecvStore> FerretOtExtRecv(
    const std::shared_ptr<link::Context>& ctx,
    const std::shared_ptr<OtRecvStore>& base_cot,
    const FerretOtExtOption& option, uint64_t ot_num) {
  YACL_ENFORCE(ctx->WorldSize() == 2);  // Make sure that OT has two parties
  YACL_ENFORCE(base_cot->IsCompactCot());

  auto ot_store = std::make_shared<OtRecvStore>(ot_num, true);  // compact mode

  const uint64_t batch_size = option.lpn_n - option.lpn_k;
  const uint64_t batch_num = (ot_num + batch_size - 1) / batch_size;

  std::vector<uint128_t> u(option.lpn_k);  // F2, but we store it in uint128_t

  // prepare u, w, where w = v ^ u * delta
  // u = cot_seed->GetChoice(idx)
  // w = cot_seed->GetBlock(idx)
  auto cot_seed = base_cot->NextSlice(option.lpn_k);
  auto working_w = cot_seed->CopyBlocks();

  // get lpn public matrix A
  uint128_t seed = GenSyncedSeed(ctx);
  LocalLinearCode<10> llc(seed, option.lpn_n, option.lpn_k);

  for (uint64_t i = 0; i < batch_num; ++i) {
    // get e
    auto e = MakeRegularRandChoices(option.lpn_t, option.lpn_n);

    // run mpcot (get r)
    std::vector<uint128_t> r(option.lpn_n);
    auto cot_batch = base_cot->NextSlice(option.mpcot_option.cot_num);

    MpCotRecv(ctx, cot_batch, option.mpcot_option, e, absl::MakeSpan(r));

    // use lpn to calculate w*A, and u*A
    std::vector<uint128_t> wa(option.lpn_n);
    std::vector<uint128_t> ua(option.lpn_n);
    llc.Encode(working_w, absl::MakeSpan(wa));

    // update u, w (first lpn_k of va^s)
    for (uint64_t j = 0; j < option.lpn_k; ++j) {
      working_w[j] = wa[j] ^ r[j];
    }

    // z = wa ^ r (time consuming)
    const uint64_t limit = std::min(batch_size, ot_num - i * batch_size);
    for (uint64_t j = 0; j < limit; ++j) {
      ot_store->SetBlock(i * batch_size + j,
                         wa[j + option.lpn_k] ^ r[j + option.lpn_k]);
    }
  }
  return ot_store;
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
               const std::shared_ptr<OtSendStore>& cot,
               const MpCotOption& option, absl::Span<uint128_t> out) {
  YACL_ENFORCE_GE(cot->Size(), option.cot_num);
  YACL_ENFORCE_EQ(out.size(), option.idx_range);

  if (option.use_cuckoo) {
    MpCotSendImpl_AnyIndices(ctx, cot, option, out);
  } else {
    MpCotSendImpl_RegularIndices(ctx, cot, option, out);
  }
}

void MpCotRecv(const std::shared_ptr<link::Context>& ctx,
               const std::shared_ptr<OtRecvStore>& cot,
               const MpCotOption& option, absl::Span<const uint64_t> idxes,
               absl::Span<uint128_t> out) {
  YACL_ENFORCE(idxes.size() > 1);
  YACL_ENFORCE_GE(cot->Size(), option.cot_num);
  YACL_ENFORCE_EQ(idxes.size(), option.idx_num);
  YACL_ENFORCE_EQ(out.size(), option.idx_range);

  if (option.use_cuckoo) {
    MpCotRecvImpl_AnyIndices(ctx, cot, option, idxes, out);
  } else {
    MpCotRecvImpl_RegularIndices(ctx, cot, option, idxes, out);
  }
}

void SpCotSend(const std::shared_ptr<link::Context>& ctx,
               const std::shared_ptr<OtSendStore>& base_cot,
               const SpCotOption& option, absl::Span<uint128_t> out) {
  YACL_ENFORCE_GE(base_cot->Size(), option.cot_num);
  YACL_ENFORCE_EQ(out.size(), option.idx_range);

  SgrrOtExtSend(ctx, base_cot, option.idx_range, out);

  // since send_buf is masked with a "receiver-unknown" value, therefore,
  // directly sending send_buf is secure.
  uint128_t send_buf = base_cot->GetDelta();  // since base_cot is not compact
  for (uint64_t i = 0; i < option.idx_range; ++i) {
    send_buf = send_buf ^ out[i];
  }
  ctx->SendAsync(ctx->NextRank(), SerializeUint128(send_buf),
                 "SpCotSend:MASKED_DELTA");
}

void SpCotRecv(const std::shared_ptr<link::Context>& ctx,
               const std::shared_ptr<OtRecvStore>& cot,
               const SpCotOption& option, uint64_t idx,
               absl::Span<uint128_t> out) {
  YACL_ENFORCE_GE(cot->Size(), option.cot_num);
  YACL_ENFORCE_EQ(out.size(), option.idx_range);
  YACL_ENFORCE_GT(option.idx_range, idx);
  // Note that in SgrrOtExtRecv, the received "out" vector has size of
  // option.range_n, with out[idx] = 0, which is different from what we want in
  // Ferret OT
  //
  // We need out[idx] = delta, since we actually needs
  // \vec{v} = \vec{w} + \vec{u} * delta, where \vec{u} contains only "1" and
  // "0", and it only has one "1" value.
  SgrrOtExtRecv(ctx, cot, option.idx_range, idx, out);

  auto masked_delta =
      DeserializeUint128(ctx->Recv(ctx->NextRank(), "SpCotRecv:MASKED_DELTA"));
  out[idx] = masked_delta;
  for (uint64_t i = 0; i < option.idx_range; ++i) {
    if (i != idx) {
      out[idx] ^= out[i];
    }
  }
}

}  // namespace yacl::crypto
