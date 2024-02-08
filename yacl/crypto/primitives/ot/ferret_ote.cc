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
#include <memory>
#include <utility>
#include <vector>

#include "yacl/base/aligned_vector.h"
#include "yacl/utils/cuckoo_index.h"
#include "yacl/utils/serialize.h"

namespace yacl::crypto {

namespace {

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

}  // namespace

uint64_t FerretCotHelper(const LpnParam& lpn_param, uint64_t /*ot_num*/) {
  uint64_t mpcot_cot = 0;
  if (lpn_param.noise_asm == LpnNoiseAsm::RegularNoise) {
    // for each mpcot invocation,
    //  idx_num = lpn_param.t (the number of non-zeros)
    //  idx_range = lpn_param.n the idx range for each index
    mpcot_cot = MpCotRNHelper(lpn_param.t, lpn_param.n);
  } else {
    YACL_THROW("Not Implemented!");
    // for each mpcot invocation,
    //  idx_num = lpn_param.t (the number of non-zeros)
    //  idx_range = lpn_param.n the idx range for each index
    mpcot_cot = MpCotUNHelper(lpn_param.t, lpn_param.n);
  }

  // The required cots are used as:
  // (1) expansion seed: kFerret_lpnK
  // (2) mpcot cot: mp_option.cot_num (just for the first batch)
  return lpn_param.k + mpcot_cot;
}

OtSendStore FerretOtExtSend(const std::shared_ptr<link::Context>& ctx,
                            const OtSendStore& base_cot,
                            const LpnParam& lpn_param, uint64_t ot_num) {
  YACL_ENFORCE(ctx->WorldSize() == 2);  // Make sure that OT has two parties
  YACL_ENFORCE(base_cot.Type() == OtStoreType::Compact);
  YACL_ENFORCE(base_cot.Size() >= FerretCotHelper(lpn_param, ot_num));
  YACL_ENFORCE(
      ot_num >= 2 * lpn_param.t,
      "ot_num is {}, which should be much greater than 2 * lpn_param.t ({})",
      ot_num, 2 * lpn_param.t);

  // get constants: the number of cot needed for mpcot phase
  const auto mpcot_cot_num = MpCotRNHelper(lpn_param.t, lpn_param.n);

  // get constants: batch information
  const uint64_t cache_size = lpn_param.k + mpcot_cot_num;
  const uint64_t batch_size = lpn_param.n - cache_size;
  const uint64_t batch_num = (ot_num + batch_size - 1) / batch_size;
  const uint128_t delta = base_cot.GetDelta();

  // prepare v (before silent expansion), where w = v ^ u * delta
  // FIX ME: "Slice" would would force to slice original OtStore from "begin" to
  // "end", it would be better to use "NextSlice" here, but it's not a const
  // function.
  auto cot_mpcot = base_cot.Slice(0, mpcot_cot_num);
  auto cot_seed = base_cot.Slice(mpcot_cot_num, mpcot_cot_num + lpn_param.k);
  auto working_v = cot_seed.CopyCotBlocks();

  // get lpn public matrix A
  uint128_t seed = GenSyncedSeed(ctx);
  LocalLinearCode<10> llc(seed, lpn_param.n, lpn_param.k);

  // placeholder for the outputs
  AlignedVector<uint128_t> out(ot_num);
  auto out_span = absl::MakeSpan(out.data(), out.size());

  // For uniform noise assumption only
  // CuckooIndex::Options option;
  // std::unique_ptr<FerretSimpleMap> simple_map;
  // if (lpn_param.noise_asm == LpnNoiseAsm::UniformNoise) {
  //   YACL_THROW("Not Implemented!");
  //   option = CuckooIndex::SelectParams(lpn_param.t, kFerretCuckooStashNum,
  //                                      kFerretCuckooHashNum);
  //   simple_map = MakeSimpleMap(option, lpn_param.n);
  // }

  auto spcot_size = lpn_param.n / lpn_param.t;
  for (uint64_t i = 0; i < batch_num; ++i) {
    // the ot generated by this batch (including the seeds for next batch if
    // necessary)
    auto batch_ot_num = std::min(lpn_param.n, ot_num - i * batch_size);
    auto working_s = out_span.subspan(i * batch_size, batch_ot_num);

    auto idx_num = lpn_param.t;
    auto idx_range = batch_ot_num;
    if (lpn_param.noise_asm == LpnNoiseAsm::RegularNoise) {
      MpCotRNSend(ctx, cot_mpcot, idx_range, idx_num, spcot_size, working_s);
    } else {
      YACL_THROW("Not Implemented!");
      // MpCotUNSend(ctx, cot_mpcot, simple_map, option, working_s);
    }

    // use lpn to calculate v*A
    // llc.Encode(in,out) would calculate out = out + in * A
    llc.Encode(working_v, working_s);

    // bool is_last_batch = (i == batch_num - 1);
    // update v (first lpn_k of va^s)
    if ((ot_num - i * batch_size) > batch_ot_num) {
      // update v for the next batch
      for (uint64_t j = 0; j < lpn_param.k; ++j) {
        working_v[j] = working_s[batch_size + j];
      }

      // manually set the cot for next batch mpcot
      cot_mpcot.ResetSlice();
      for (uint64_t j = 0; j < mpcot_cot_num; ++j) {
        cot_mpcot.SetCompactBlock(j, working_s[batch_size + lpn_param.k + j]);
      }
    } else {
      break;
    }
  }

  return MakeCompactOtSendStore(std::move(out), delta);
}

OtRecvStore FerretOtExtRecv(const std::shared_ptr<link::Context>& ctx,
                            const OtRecvStore& base_cot,
                            const LpnParam& lpn_param, uint64_t ot_num) {
  YACL_ENFORCE(ctx->WorldSize() == 2);  // Make sure that OT has two parties
  YACL_ENFORCE(base_cot.Type() == OtStoreType::Compact);
  YACL_ENFORCE(base_cot.Size() >= FerretCotHelper(lpn_param, ot_num));
  YACL_ENFORCE(
      ot_num >= 2 * lpn_param.t,
      "ot_num is {}, which should be much greater than 2 * lpn_param.t ({})",
      ot_num, 2 * lpn_param.t);

  // get constants: the number of cot needed for mpcot phase
  const auto mpcot_cot_num = MpCotRNHelper(lpn_param.t, lpn_param.n);

  // get constants: batch information
  const uint64_t cache_size = lpn_param.k + mpcot_cot_num;
  const uint64_t batch_size = lpn_param.n - cache_size;
  const uint64_t batch_num = (ot_num + batch_size - 1) / batch_size;

  // F2, but we store it in uint128_t
  AlignedVector<uint128_t> u(lpn_param.k);

  // prepare u, w, where w = v ^ u * delta
  // FIX ME: "Slice" would would force to slice original OtStore from "begin" to
  // "end", it would be better to use "NextSlice" here, but it's not a const
  // function.
  auto cot_mpcot = base_cot.Slice(0, mpcot_cot_num);
  auto cot_seed = base_cot.Slice(mpcot_cot_num, mpcot_cot_num + lpn_param.k);
  auto working_w = cot_seed.CopyBlocks();

  // get lpn public matrix A
  uint128_t seed = GenSyncedSeed(ctx);
  LocalLinearCode<10> llc(seed, lpn_param.n, lpn_param.k);

  // placeholder for the outputs
  AlignedVector<uint128_t> out(ot_num);
  auto out_span = absl::MakeSpan(out);

  // For uniform noise assumption only
  // CuckooIndex::Options option;
  // std::unique_ptr<FerretSimpleMap> simple_map;
  // if (lpn_param.noise_asm == LpnNoiseAsm::UniformNoise) {
  //   YACL_THROW("Not Implemented!");
  //   option = CuckooIndex::SelectParams(lpn_param.t, kFerretCuckooStashNum,
  //                                      kFerretCuckooHashNum);
  //   simple_map = MakeSimpleMap(option, lpn_param.n);
  // }

  auto spcot_size = lpn_param.n / lpn_param.t;
  for (uint64_t i = 0; i < batch_num; ++i) {
    // the ot generated by this batch (including the seeds for next batch if
    // necessary)
    auto batch_ot_num = std::min(lpn_param.n, ot_num - i * batch_size);
    auto working_r = out_span.subspan(i * batch_size, batch_ot_num);

    // run mpcot (get r)
    auto idx_num = lpn_param.t;
    auto idx_range = batch_ot_num;

    if (lpn_param.noise_asm == LpnNoiseAsm::RegularNoise) {
      MpCotRNRecv(ctx, cot_mpcot, idx_range, idx_num, spcot_size, working_r);
    } else {
      YACL_THROW("Not Implemented!");
      // MpCotUNRecv(ctx, cot_mpcot, simple_map, option, e, working_r);
    }

    // use lpn to calculate w*A, and u*A
    // llc.Encode(in,out) would calculate out = out + in * A
    llc.Encode(working_w, working_r);

    // bool is_last_batch = (i == batch_num - 1);
    if ((ot_num - i * batch_size) > batch_ot_num) {
      // update u, w (first lpn_k of va^s)
      for (uint64_t j = 0; j < lpn_param.k; ++j) {
        working_w[j] = working_r[batch_size + j];
      }

      // manually set the cot for next batch mpcot
      cot_mpcot.ResetSlice();
      for (uint64_t j = 0; j < mpcot_cot_num; ++j) {
        cot_mpcot.SetBlock(j, working_r[batch_size + j + lpn_param.k]);
      }
    } else {
      break;
    }
  }

  return MakeCompactOtRecvStore(std::move(out));
}

void FerretOtExtSend_cheetah(const std::shared_ptr<link::Context>& ctx,
                             const OtSendStore& base_cot,
                             const LpnParam& lpn_param, uint64_t ot_num,
                             absl::Span<uint128_t> out) {
  YACL_ENFORCE(ctx->WorldSize() == 2);  // Make sure that OT has two parties
  YACL_ENFORCE(base_cot.Type() == OtStoreType::Compact);
  YACL_ENFORCE(base_cot.Size() >= FerretCotHelper(lpn_param, ot_num));

  // get constants: the number of cot needed for mpcot phase
  const auto mpcot_cot_num = MpCotRNHelper(lpn_param.t, lpn_param.n);

  // get constants: batch information
  const uint64_t cache_size = lpn_param.k + mpcot_cot_num;
  const uint64_t batch_size = lpn_param.n - cache_size;
  const uint64_t batch_num = (ot_num + batch_size - 1) / batch_size;
  // const uint128_t delta = base_cot.GetDelta();

  // prepare v (before silent expansion), where w = v ^ u * delta
  auto cot_seed = base_cot.Slice(0, lpn_param.k);
  auto cot_mpcot = base_cot.Slice(lpn_param.k, lpn_param.k + mpcot_cot_num);
  auto working_v = cot_seed.CopyCotBlocks();

  // get lpn public matrix A
  uint128_t seed = GenSyncedSeed(ctx);
  LocalLinearCode<10> llc(seed, lpn_param.n, lpn_param.k);

  // placeholder for the outputs
  YACL_ENFORCE(out.size() == ot_num);
  // AlignedVector<uint128_t> out(ot_num);
  auto out_span = out;

  // For uniform noise assumption only
  // CuckooIndex::Options option;
  // std::unique_ptr<FerretSimpleMap> simple_map;
  // if (lpn_param.noise_asm == LpnNoiseAsm::UniformNoise) {
  //   YACL_THROW("Not Implemented!");
  //   option = CuckooIndex::SelectParams(lpn_param.t, kFerretCuckooStashNum,
  //                                      kFerretCuckooHashNum);
  //   simple_map = MakeSimpleMap(option, lpn_param.n);
  // }

  auto spcot_size = lpn_param.n / lpn_param.t;
  for (uint64_t i = 0; i < batch_num; ++i) {
    // the ot generated by this batch (including the seeds for next batch if
    // necessary)
    auto batch_ot_num = std::min(lpn_param.n, ot_num - i * batch_size);
    auto working_s = out_span.subspan(i * batch_size, batch_ot_num);

    auto idx_num = lpn_param.t;
    auto idx_range = batch_ot_num;
    if (lpn_param.noise_asm == LpnNoiseAsm::RegularNoise) {
      MpCotRNSend(ctx, cot_mpcot, idx_range, idx_num, spcot_size, working_s);
    } else {
      YACL_THROW("Not Implemented!");
      // MpCotUNSend(ctx, cot_mpcot, simple_map, option, working_s);
    }

    // use lpn to calculate v*A
    // llc.Encode(in,out) would calculate out = out + in * A
    llc.Encode(working_v, working_s);

    // bool is_last_batch = (i == batch_num - 1);
    // update v (first lpn_k of va^s)
    if ((ot_num - i * batch_size) > batch_ot_num) {
      // update v for the next batch
      // for (uint64_t j = 0; j < lpn_param.k; ++j) {
      //   working_v[j] = working_s[batch_size + j];
      // }
      memcpy(working_v.data(), working_s.data() + batch_size,
             lpn_param.k * sizeof(uint128_t));

      // manually set the cot for next batch mpcot
      cot_mpcot.ResetSlice();
      for (uint64_t j = 0; j < mpcot_cot_num; ++j) {
        cot_mpcot.SetCompactBlock(j, working_s[batch_size + lpn_param.k + j]);
      }
    } else {
      break;
    }
  }

  // return MakeCompactOtSendStore(std::move(out), delta);
}

void FerretOtExtRecv_cheetah(const std::shared_ptr<link::Context>& ctx,
                             const OtRecvStore& base_cot,
                             const LpnParam& lpn_param, uint64_t ot_num,
                             absl::Span<uint128_t> out) {
  YACL_ENFORCE(ctx->WorldSize() == 2);  // Make sure that OT has two parties
  YACL_ENFORCE(base_cot.Type() == OtStoreType::Compact);
  YACL_ENFORCE(base_cot.Size() >= FerretCotHelper(lpn_param, ot_num));

  // get constants: the number of cot needed for mpcot phase
  const auto mpcot_cot_num = MpCotRNHelper(lpn_param.t, lpn_param.n);

  // get constants: batch information
  const uint64_t cache_size = lpn_param.k + mpcot_cot_num;
  const uint64_t batch_size = lpn_param.n - cache_size;
  const uint64_t batch_num = (ot_num + batch_size - 1) / batch_size;

  // F2, but we store it in uint128_t
  AlignedVector<uint128_t> u(lpn_param.k);

  // prepare u, w, where w = v ^ u * delta
  auto cot_seed = base_cot.Slice(0, lpn_param.k);
  auto cot_mpcot = base_cot.Slice(lpn_param.k, lpn_param.k + mpcot_cot_num);
  auto working_w = cot_seed.CopyBlocks();

  // get lpn public matrix A
  uint128_t seed = GenSyncedSeed(ctx);
  LocalLinearCode<10> llc(seed, lpn_param.n, lpn_param.k);

  // placeholder for the outputs
  // AlignedVector<uint128_t> out(ot_num);
  YACL_ENFORCE(out.size() == ot_num);
  auto out_span = out;

  // For uniform noise assumption only
  // CuckooIndex::Options option;
  // std::unique_ptr<FerretSimpleMap> simple_map;
  // if (lpn_param.noise_asm == LpnNoiseAsm::UniformNoise) {
  //   YACL_THROW("Not Implemented!");
  //   option = CuckooIndex::SelectParams(lpn_param.t, kFerretCuckooStashNum,
  //                                      kFerretCuckooHashNum);
  //   simple_map = MakeSimpleMap(option, lpn_param.n);
  // }

  auto spcot_size = lpn_param.n / lpn_param.t;
  for (uint64_t i = 0; i < batch_num; ++i) {
    // the ot generated by this batch (including the seeds for next batch if
    // necessary)
    auto batch_ot_num = std::min(lpn_param.n, ot_num - i * batch_size);
    auto working_r = out_span.subspan(i * batch_size, batch_ot_num);

    // run mpcot (get r)
    auto idx_num = lpn_param.t;
    auto idx_range = batch_ot_num;

    if (lpn_param.noise_asm == LpnNoiseAsm::RegularNoise) {
      MpCotRNRecv(ctx, cot_mpcot, idx_range, idx_num, spcot_size, working_r);
    } else {
      YACL_THROW("Not Implemented!");
      // MpCotUNRecv(ctx, cot_mpcot, simple_map, option, e, working_r);
    }

    // use lpn to calculate w*A, and u*A
    // llc.Encode(in,out) would calculate out = out + in * A
    llc.Encode(working_w, working_r);

    // bool is_last_batch = (i == batch_num - 1);
    if ((ot_num - i * batch_size) > batch_ot_num) {
      // update u, w (first lpn_k of va^s)
      // for (uint64_t j = 0; j < lpn_param.k; ++j) {
      //   working_w[j] = working_r[batch_size + j];
      // }
      memcpy(working_w.data(), working_r.data() + batch_size,
             lpn_param.k * sizeof(uint128_t));

      // manually set the cot for next batch mpcot
      cot_mpcot.ResetSlice();
      for (uint64_t j = 0; j < mpcot_cot_num; ++j) {
        cot_mpcot.SetBlock(j, working_r[batch_size + j + lpn_param.k]);
      }
    } else {
      break;
    }
  }
}

}  // namespace yacl::crypto
