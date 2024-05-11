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

#include "yacl/kernel/algorithms/softspoken_ote.h"

#include <sys/socket.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>

#include "yacl/base/aligned_vector.h"
#include "yacl/base/byte_container_view.h"
#include "yacl/crypto/tools/common.h"
#include "yacl/math/f2k/f2k.h"
#include "yacl/utils/matrix_utils.h"
#include "yacl/utils/serialize.h"

#ifndef __aarch64__
// sse
#include <emmintrin.h>
#include <smmintrin.h>
// pclmul
#include <wmmintrin.h>
#else
#include "sse2neon.h"
#endif

#include <array>
#include <vector>

namespace yacl::crypto {

namespace {

constexpr uint64_t kBatchSize = 128;
constexpr uint64_t kKappa = 128;
constexpr size_t kS = 64;  // statistical security parameter

template <typename T = uint64_t>
struct CheckMsg {
  T x = 0;
  std::array<T, kKappa> t{0};

  // pack the check_msg into one byte buffer (for networking)
  Buffer Pack() {
    Buffer out((kKappa + 1) * sizeof(T));
    memcpy(out.data<uint8_t>(), &x, sizeof(T));
    memcpy(out.data<uint8_t>() + sizeof(T), t.data(), sizeof(T) * kKappa);
    return out;
  }

  // unpack the check_msg from byte buffer (for networking)
  void Unpack(ByteContainerView buf) {
    std::memcpy(&x, buf.data(), sizeof(T));
    std::memcpy(t.data(), buf.data() + sizeof(T), kKappa * sizeof(T));
  }
};

inline dynamic_bitset<uint128_t> ExtendChoice(
    const dynamic_bitset<uint128_t>& choices, size_t final_size) {
  // Extend choices to batch_num * kBlockNum bits
  // 1st part (valid_ot_num bits): original ot choices
  // 2nd part (verify_ot_num bits): rand bits used for checking
  // 3rd party (the rest bits): padding 1;
  dynamic_bitset<uint128_t> choices_ext = choices;

  // 2nd part Extension
  Prg<bool> gen;
  for (size_t i = 0; i < kS; i++) {
    choices_ext.push_back(gen());
  }

  // 3rd part Extension
  choices_ext.resize(final_size);
  return choices_ext;
}

inline void XorBlock(absl::Span<const uint128_t> in, absl::Span<uint128_t> out,
                     const uint128_t block) {
  YACL_ENFORCE(out.size() >= in.size());
  auto reg_block = _mm_load_si128(reinterpret_cast<const __m128i*>(&block));
  for (uint64_t i = 0; i < in.size(); ++i) {
    out[i] = reinterpret_cast<uint128_t>(
        _mm_xor_si128(reinterpret_cast<__m128i>(in[i]), reg_block));
  }
}

// XorReduce
// Implementation mostly from:
// https://github.com/osu-crypto/libOTe/blob/master/libOTe/Vole/SoftSpokenOT/SmallFieldVole.cpp
template <uint64_t k>
inline void XorReduce(absl::Span<uint128_t> inout) {
  XorReduce<k - 1>(inout);
  const uint64_t buf_size = inout.size();
  constexpr uint64_t stride = 1 << (k - 1);
  for (uint64_t i = 0; i < buf_size; i += 2 * stride) {
    for (uint64_t j = 0; j < k; ++j) {
      inout[i + j] = reinterpret_cast<uint128_t>(
          _mm_xor_si128(reinterpret_cast<__m128i>(inout[i + j]),
                        reinterpret_cast<__m128i>(inout[i + j + stride])));
    }
    inout[i + k] = inout[i + stride];
  }
}

template <>
inline void XorReduce<0>([[maybe_unused]] absl::Span<uint128_t> inout) {}

inline void XorReduce(uint64_t k, absl::Span<uint128_t> inout) {
  YACL_ENFORCE(k <= 64);
  const uint64_t buf_size = inout.size();

  for (uint64_t depth = 1; depth <= k; ++depth) {
    uint64_t stride = static_cast<uint64_t>(1) << (depth - 1);
    for (uint64_t i = 0; i < buf_size; i += 2 * stride) {
      for (uint64_t j = 0; j < depth; ++j) {
        inout[i + j] ^= inout[i + j + stride];
      }
      inout[i + depth] = inout[i + stride];
    }
  }
}

inline void XorReduceImpl(uint64_t k, absl::Span<uint128_t> inout) {
  switch (k) {
#define SWITCH_CASE(n)   \
  case n:                \
    XorReduce<n>(inout); \
    break;

    SWITCH_CASE(1);
    SWITCH_CASE(2);
    SWITCH_CASE(3);
    SWITCH_CASE(4);
    SWITCH_CASE(5);
    SWITCH_CASE(6);
    SWITCH_CASE(7);
    SWITCH_CASE(8);

#undef SWITCH_CASE
    default:
      XorReduce(k, inout);
      break;
  }
}

}  // namespace

SoftspokenOtExtSender::SoftspokenOtExtSender(uint64_t k, uint64_t step,
                                             bool mal, bool compact)
    : k_(k), step_(step), mal_(mal), compact_(compact) {
  counter_ = 0;
  pprf_num_ = (kKappa + k_ - 1) / k_;
  pprf_range_ = static_cast<uint64_t>(1) << k_;
  const uint64_t empty_num =
      pprf_range_ - (1 << (kKappa - (pprf_num_ - 1) * k_));
  const uint128_t total_size = pprf_num_ * pprf_range_ - empty_num;

  // punctured_leaves_ would save leaves in all pprf
  punctured_leaves_ = UninitAlignedVector<uint128_t>(total_size);
  // punctured_idx_ would record all punctured indexs
  punctured_idx_ = UninitAlignedVector<uint128_t>(pprf_num_);
  // remove the empty entries in punctured_leaves_
  compress_leaves_ = UninitAlignedVector<uint128_t>(total_size - pprf_num_);
  // init delta
  delta_ = MakeUint128(0, 0);

  // set default step or super batch
  if (step_ == 0) {
    if (k <= 2) {
      step_ = 64;
    } else if (k <= 4) {
      step_ = 32;
    } else {
      step_ = 16;
    }
  }
}

SoftspokenOtExtReceiver::SoftspokenOtExtReceiver(uint64_t k, uint64_t step,
                                                 bool mal, bool compact)
    : k_(k), step_(step), mal_(mal), compact_(compact) {
  counter_ = 0;
  pprf_num_ = (kKappa + k_ - 1) / k_;
  pprf_range_ = static_cast<uint64_t>(1) << k_;
  const uint64_t empty_num =
      pprf_range_ - (1 << (kKappa - (pprf_num_ - 1) * k_));
  const uint64_t total_size = pprf_num_ * pprf_range_ - empty_num;
  all_leaves_ = UninitAlignedVector<uint128_t>(total_size);

  // set default step or super batch
  if (step_ == 0) {
    if (k <= 2) {
      step_ = 64;
    } else if (k <= 4) {
      step_ = 32;
    } else {
      step_ = 16;
    }
  }
}

void SoftspokenOtExtSender::OneTimeSetup(
    const std::shared_ptr<link::Context>& ctx) {
  if (inited_) {
    return;
  }

  // generate base-OT
  auto choices = SecureRandBits(kKappa);
  auto base_ot = BaseOtRecv(ctx, choices, kKappa);

  OneTimeSetup(ctx, base_ot);
}

void SoftspokenOtExtSender::OneTimeSetup(
    const std::shared_ptr<link::Context>& ctx, const OtRecvStore& base_ot) {
  if (inited_) {
    return;
  }
  YACL_ENFORCE(base_ot.Size() == kKappa);
  // FIXME: Copy base_ot, since NextSlice is not const
  auto dup_base_ot = base_ot;
  // set delta

  if (compact_) {
    dup_base_ot.SetBlock(0, MakeUint128(0, 0));
    dup_base_ot.SetChoice(0, 1);
  }

  delta_ = dup_base_ot.CopyChoice().data()[0];

  auto recv_size = 128 * 2 * sizeof(uint128_t) + pprf_num_ * (mal_ ? 64 : 0);
  auto recv_buf = ctx->Recv(ctx->NextRank(), "SGRR_OTE:RECV-CORR");
  YACL_ENFORCE((uint64_t)recv_buf.size() == recv_size);
  auto recv_span = absl::MakeSpan((recv_buf.data<const uint8_t>()), recv_size);
  auto single_buf_size = SgrrOtExtHelper(pprf_range_, mal_);
  // One-time Setup for Softspoken
  // k 1-out-of-2 ROT to (2^k-1)-out-of-(2^k) ROT
  for (uint64_t i = 0; i < pprf_num_; ++i) {
    const uint64_t k_limit = std::min(k_, kKappa - i * k_);
    const uint64_t range_limit = static_cast<uint64_t>(1) << k_limit;
    // i-th OT instances
    auto sub_ot = dup_base_ot.NextSlice(k_limit);
    // TODO(@wenfan): [low efficiency] It would copy dynamic_bitset<uint128_t>.
    // punctured index for i-th pprf
    punctured_idx_[i] = sub_ot.CopyChoice().data()[0];
    // punctured leaves for the i-th pprf
    auto leaves =
        absl::MakeSpan(punctured_leaves_.data() + i * pprf_range_, range_limit);
    // prepare for cur_recv_buf
    auto cur_buf_size = SgrrOtExtHelper(range_limit, mal_);
    auto cur_recv_buf = recv_span.subspan(single_buf_size * i, cur_buf_size);
    // SgrrOtExt
    SgrrOtExtRecv_fixed_index(sub_ot, range_limit, leaves, cur_recv_buf, mal_);
    // if the j-th bit of punctured index is 1, set mask as all one;
    // set mask as all zero otherwise.
    for (uint64_t j = 0; j < k_limit; ++j) {
      if (punctured_idx_[i] & (1 << j)) {
        p_idx_mask_[i * k_ + j] = Uint128Max();  // all one
      } else {
        p_idx_mask_[i * k_ + j] = Uint128Min();  // all zero
      }
    }
    // move leaves[0] to punctured entry
    leaves[punctured_idx_[i]] = leaves[0];
    // copy entry 1 to range_limit for leaves into c_leaves
    auto c_leaves = absl::MakeSpan(
        compress_leaves_.data() + i * (pprf_range_ - 1), range_limit - 1);
    for (uint64_t j = 0; j < range_limit - 1; ++j) {
      c_leaves[j] = leaves[j + 1];
    }
    // set punctured entry as zero
    leaves[punctured_idx_[i]] = Uint128Min();
  }
  inited_ = true;
}

void SoftspokenOtExtReceiver::OneTimeSetup(
    const std::shared_ptr<link::Context>& ctx) {
  if (inited_) {
    return;
  }
  // generate base-OT
  auto base_ot = BaseOtSend(ctx, kKappa);

  OneTimeSetup(ctx, base_ot);
}

void SoftspokenOtExtReceiver::OneTimeSetup(
    const std::shared_ptr<link::Context>& ctx, const OtSendStore& base_ot) {
  if (inited_) {
    return;
  }
  YACL_ENFORCE(base_ot.Size() == kKappa);
  // FIXME: Copy base_ot, since NextSlice is not const
  auto dup_base_ot = base_ot;
  if (compact_) {
    dup_base_ot.SetNormalBlock(0, 0, MakeUint128(0, 0));
    dup_base_ot.SetNormalBlock(0, 1, MakeUint128(0, 0));
  }
  // Send Message Buffer
  auto send_size = 128 * 2 * sizeof(uint128_t) + pprf_num_ * (mal_ ? 64 : 0);
  auto send_buf = Buffer(send_size);
  auto send_span = absl::MakeSpan(send_buf.data<uint8_t>(), send_size);
  auto single_buf_size = SgrrOtExtHelper(pprf_range_, mal_);
  // One-time Setup for Softspoken
  // k 1-out-of-2 ROT to (2^k-1)-out-of-(2^k) ROT
  for (uint64_t i = 0; i < pprf_num_; ++i) {
    const uint64_t k_limit = std::min(k_, kKappa - i * k_);
    const uint64_t range_limit = static_cast<uint64_t>(1) << k_limit;
    // i-th OT instances
    auto sub_ot = dup_base_ot.NextSlice(k_limit);
    // leaves in i-th pprf
    auto leaves =
        absl::MakeSpan(all_leaves_.data() + i * pprf_range_, range_limit);
    // prepare cur_send_buf
    auto cur_buf_size = SgrrOtExtHelper(range_limit, mal_);
    auto cur_send_span = send_span.subspan(i * single_buf_size, cur_buf_size);
    // SgrrOtExt
    SgrrOtExtSend_fixed_index(sub_ot, range_limit, leaves, cur_send_span, mal_);
  }
  ctx->SendAsync(ctx->NextRank(), ByteContainerView(send_buf),
                 "SGRR_OTE:SEND-CORR");
  inited_ = true;
}

void SoftspokenOtExtSender::GenRot(const std::shared_ptr<link::Context>& ctx,
                                   uint64_t num_ot, OtSendStore* out) {
  YACL_ENFORCE(out->Size() == num_ot);
  YACL_ENFORCE(out->Type() == OtStoreType::Normal);
  std::vector<std::array<uint128_t, 2>> send_blocks(num_ot);
  Send(ctx, absl::MakeSpan(send_blocks), false);
  for (uint64_t i = 0; i < num_ot; ++i) {
    out->SetNormalBlock(i, 0, send_blocks[i][0]);
    out->SetNormalBlock(i, 1, send_blocks[i][1]);
  }
}

void SoftspokenOtExtSender::GenCot(const std::shared_ptr<link::Context>& ctx,
                                   uint64_t num_ot, OtSendStore* out) {
  YACL_ENFORCE(out->Size() == num_ot);
  YACL_ENFORCE(out->Type() == OtStoreType::Compact);
  std::vector<std::array<uint128_t, 2>> send_blocks(num_ot);
  Send(ctx, absl::MakeSpan(send_blocks), true);
  out->SetDelta(GetDelta());
  for (uint64_t i = 0; i < num_ot; ++i) {
    out->SetCompactBlock(i, send_blocks[i][0]);
  }
}

OtSendStore SoftspokenOtExtSender::GenRot(
    const std::shared_ptr<link::Context>& ctx, uint64_t num_ot) {
  OtSendStore out(num_ot, OtStoreType::Normal);
  GenRot(ctx, num_ot, &out);
  return out;
}

OtSendStore SoftspokenOtExtSender::GenCot(
    const std::shared_ptr<link::Context>& ctx, uint64_t num_ot) {
  OtSendStore out(num_ot, OtStoreType::Compact);
  GenCot(ctx, num_ot, &out);
  return out;
}

void SoftspokenOtExtReceiver::GenRot(const std::shared_ptr<link::Context>& ctx,
                                     uint64_t num_ot, OtRecvStore* out) {
  YACL_ENFORCE(out->Size() == num_ot);
  YACL_ENFORCE(out->Type() == OtStoreType::Normal);
  auto choices = SecureRandBits<dynamic_bitset<uint128_t>>(num_ot);
  auto recv_blocks = std::vector<uint128_t>(num_ot);
  Recv(ctx, choices, absl::MakeSpan(recv_blocks), false);

  // out->SetChoices did not implement
  // [Warning] low efficiency
  for (uint64_t i = 0; i < num_ot; ++i) {
    out->SetBlock(i, recv_blocks[i]);
    out->SetChoice(i, choices[i]);
  }
}

void SoftspokenOtExtReceiver::GenRot(const std::shared_ptr<link::Context>& ctx,
                                     const dynamic_bitset<uint128_t>& choices,
                                     OtRecvStore* out) {
  const uint64_t num_ot = choices.size();
  YACL_ENFORCE(out->Size() == num_ot);
  YACL_ENFORCE(out->Type() == OtStoreType::Normal);
  auto recv_blocks = std::vector<uint128_t>(num_ot);
  Recv(ctx, choices, absl::MakeSpan(recv_blocks), false);

  // out->SetChoices did not implement
  // [Warning] low efficiency
  for (uint64_t i = 0; i < num_ot; ++i) {
    out->SetBlock(i, recv_blocks[i]);
    out->SetChoice(i, choices[i]);
  }
}

void SoftspokenOtExtReceiver::GenCot(const std::shared_ptr<link::Context>& ctx,
                                     uint64_t num_ot, OtRecvStore* out) {
  auto choices = SecureRandBits<dynamic_bitset<uint128_t>>(num_ot);
  GenCot(ctx, choices, out);
}

void SoftspokenOtExtReceiver::GenCot(const std::shared_ptr<link::Context>& ctx,
                                     const dynamic_bitset<uint128_t>& choices,
                                     OtRecvStore* out) {
  const uint64_t num_ot = choices.size();
  YACL_ENFORCE(out->Size() == num_ot);
  YACL_ENFORCE(out->Type() ==
               (compact_ ? OtStoreType::Compact : OtStoreType::Normal));
  auto recv_blocks = std::vector<uint128_t>(num_ot);
  Recv(ctx, choices, absl::MakeSpan(recv_blocks), true);
  // out->SetChoices did not implement
  // [Warning] low efficiency
  if (compact_) {
    for (uint64_t i = 0; i < num_ot; ++i) {
      out->SetBlock(i, recv_blocks[i]);
    }
  } else {
    for (uint64_t i = 0; i < num_ot; ++i) {
      out->SetBlock(i, recv_blocks[i]);
      out->SetChoice(i, choices[i]);
    }
  }
}

// OtStore-style interface
OtRecvStore SoftspokenOtExtReceiver::GenRot(
    const std::shared_ptr<link::Context>& ctx, uint64_t num_ot) {
  OtRecvStore out(num_ot, OtStoreType::Normal);
  // [Warning] low efficiency.
  GenRot(ctx, num_ot, &out);
  return out;
}

OtRecvStore SoftspokenOtExtReceiver::GenRot(
    const std::shared_ptr<link::Context>& ctx,
    const dynamic_bitset<uint128_t>& choices) {
  OtRecvStore out(choices.size(), OtStoreType::Normal);
  // [Warning] low efficiency.
  GenRot(ctx, choices, &out);
  return out;
}

// OtStore-style interface
OtRecvStore SoftspokenOtExtReceiver::GenCot(
    const std::shared_ptr<link::Context>& ctx, uint64_t num_ot) {
  OtRecvStore out(num_ot, OtStoreType::Normal);
  if (compact_) {
    out = OtRecvStore(num_ot, OtStoreType::Compact);
  }
  // [Warning] low efficiency.
  GenCot(ctx, num_ot, &out);
  return out;
}

// Generate Smallfield VOLE and Subspace VOLE
// Reference: https://eprint.iacr.org/2022/192.pdf Figure 7 & Figure 8
// s.t.  W = choice * delta + V
OtRecvStore SoftspokenOtExtReceiver::GenCot(
    const std::shared_ptr<link::Context>& ctx,
    const dynamic_bitset<uint128_t>& choices) {
  OtRecvStore out(choices.size(), OtStoreType::Normal);
  if (compact_) {
    out = OtRecvStore(choices.size(), OtStoreType::Compact);
  }
  // [Warning] low efficiency.
  GenCot(ctx, choices, &out);
  return out;
}

// Generate Smallfield VOLE and Subspace VOLE
// Reference: https://eprint.iacr.org/2022/192.pdf Figure 7 & Figure 8
// s.t.  V = choice * delta + W
void SoftspokenOtExtSender::GenSfVole(absl::Span<uint128_t> hash_buff,
                                      absl::Span<uint128_t> xor_buff,
                                      absl::Span<uint128_t> u,
                                      absl::Span<uint128_t> V) {
  YACL_ENFORCE(V.size() == 128);

  // Notice: It should generate the pesudorandomness for smallfield VOLE by PRG
  // But generating the pesudorandomness through "refresh seed + CrHash" has
  // much better performance

  // 1. Refresh seed
  XorBlock(absl::MakeSpan(compress_leaves_), hash_buff, counter_);
  ++counter_;
  // 2. perform Crhash
  ParaCrHashInplace_128(hash_buff);
  // 3. convert compress_seed_ to "real" location
  {
    uint64_t hash_offset = 0;
    uint64_t xor_offset = 0;
    uint64_t range = pprf_range_ - 1;
    uint64_t hash_size = hash_buff.size();
    for (uint64_t i = 0; i < pprf_num_; ++i) {
      const auto limit = std::min(range, hash_size - hash_offset);
      for (uint64_t j = 0; j < limit; ++j) {
        xor_buff[xor_offset + 1 + j] = hash_buff[hash_offset + j];  // copy
      }
      xor_buff[xor_offset] = Uint128Min();
      std::swap(
          xor_buff[xor_offset],
          xor_buff[xor_offset + punctured_idx_[i]]);  // recover punctured entry
      hash_offset += range;                           // hash_offset = i * range
      xor_offset += pprf_range_;  // xor_offset = i * pprf_range
    }
  }

  // 4. tensor product: \sum x PRG(M_x)
  XorReduceImpl(k_, absl::MakeSpan(xor_buff));

  // 5. compute delta \sum PRG(M_x) - \sum x PRG(M_x)
  {
    uint64_t V_offset = 0;
    uint64_t xor_offset = 0;
    for (uint64_t i = 0; i < pprf_num_; ++i) {
      // U = \sum PRG(M_x)
      u[i] ^= xor_buff[xor_offset];
      const uint64_t k_limit = std::min(k_, kKappa - V_offset);
      for (uint64_t j = 0; j < k_limit; ++j) {
        // if punctured_idx_[i] & (1<<j) == false, mask would be zero
        V[V_offset + j] =
            xor_buff[xor_offset + 1 + j] ^ (u[i] & p_idx_mask_[V_offset + j]);
      }
      V_offset += k_;             // V_offset = i * k
      xor_offset += pprf_range_;  // hash_offset = i * pprf_range
    }
  }

  if (compact_) {
    V[0] = MakeUint128(0, 0);
  }
}

// Generate Smallfield VOLE and Subspace VOLE
// Reference: https://eprint.iacr.org/2022/192.pdf Figure 7 & Figure 8
// s.t.  W = choice * delta + V
void SoftspokenOtExtReceiver::GenSfVole(const uint128_t choice,
                                        absl::Span<uint128_t> xor_buff,
                                        absl::Span<uint128_t> u,
                                        absl::Span<uint128_t> W) {
  YACL_ENFORCE(W.size() == 128);

  // Notice: It should generate the pesudorandomness for smallfield VOLE by PRG
  // But generating the pesudorandomness through "refresh seed + CrHash" has
  // much better performance

  // 1. refresh seed
  XorBlock(absl::MakeConstSpan(all_leaves_),
           absl::MakeSpan(xor_buff).subspan(0, all_leaves_.size()), counter_);
  ++counter_;
  // 2. perform CrHash
  ParaCrHashInplace_128(
      absl::MakeSpan(xor_buff).subspan(0, all_leaves_.size()));
  // 3. tensor product: \sum x PRG(M_x)
  XorReduceImpl(k_, absl::MakeSpan(xor_buff));
  // 4. convert to chosen choices
  {
    uint64_t W_offset = 0;
    uint64_t xor_offset = 0;
    for (uint64_t i = 0; i < pprf_num_; ++i) {
      // U = \sum PRG(M_x)
      u[i] = choice ^ xor_buff[xor_offset];
      const uint64_t k_limit = std::min(k_, kKappa - W_offset);
      for (uint64_t j = 0; j < k_limit; ++j) {
        W[W_offset + j] = xor_buff[xor_offset + 1 + j];
      }
      W_offset += k_;             // W_offset = i * k;
      xor_offset += pprf_range_;  // xor_offset = i * pprf_range;
    }
  }
  if (compact_) {
    W[0] = choice;
  }
}

// old style interface
void SoftspokenOtExtSender::Send(
    const std::shared_ptr<link::Context>& ctx,
    absl::Span<std::array<uint128_t, 2>> send_blocks, bool cot) {
  if (!inited_) {
    OneTimeSetup(ctx);
  }

  const uint64_t& step = step_;
  const auto& delta = delta_;
  const uint64_t batch_size = kBatchSize;
  const uint64_t super_batch_size = step * batch_size;
  const uint64_t numOt = send_blocks.size();
  const uint64_t expand_numOt =
      (numOt + kS + kBatchSize - 1) / kBatchSize * kBatchSize;
  const uint64_t super_batch_num = numOt / super_batch_size;
  const uint64_t batch_offset = super_batch_num * super_batch_size;
  const uint64_t batch_num =
      (expand_numOt - batch_offset + kBatchSize - 1) / kBatchSize;
  const uint64_t all_batch_num = super_batch_num * step + batch_num;
  YACL_ENFORCE(all_batch_num * kBatchSize == expand_numOt);

  UninitAlignedVector<std::array<uint128_t, kKappa>, 32> allV(all_batch_num);
  // OT extension
  // AVX need to be aligned to 32 bytes.
  // Extra one array for consitency check in batch_num for-loop.
  UninitAlignedVector<std::array<uint128_t, kKappa>, 32> V(step + 1);
  UninitAlignedVector<std::array<uint128_t, kKappa>, 32> V_xor_delta(step + 1);
  // Hash Buffer to perform AES/PRG
  // Xor Buffer to perform XorReduce ( \sum x PRG(M_x) )
  auto hash_buff = UninitAlignedVector<uint128_t>(compress_leaves_.size());
  auto xor_buff = UninitAlignedVector<uint128_t>(pprf_num_ * pprf_range_, 0);

  // deal with super batch
  for (uint64_t t = 0; t < super_batch_num; ++t) {
    // The same as IKNP OTe, see `yacl/crypto/primitive/ot/iknp_ote_cc`
    // 1. receive the masked choices
    auto recv_buff = ctx->Recv(ctx->NextRank(), "softspoken_switch_u");
    auto recv_U = absl::MakeSpan(static_cast<uint128_t*>(recv_buff.data()),
                                 recv_buff.size() / sizeof(uint128_t));
    YACL_ENFORCE(recv_U.size() == step * pprf_num_);

    for (uint64_t s = 0; s < step; ++s) {
      // 2. smallfield/subspace VOLE
      GenSfVole(absl::MakeSpan(hash_buff), absl::MakeSpan(xor_buff),
                absl::MakeSpan(recv_U.data() + s * pprf_num_, pprf_num_),
                absl::MakeSpan(V[s]));
      if (mal_) {
        allV[t * step + s] = V[s];
      }

      // 3. Matrix Transpose
      MatrixTranspose128(&V[s]);
      XorBlock(absl::MakeSpan(V[s]), absl::MakeSpan(V_xor_delta[s]), delta);
      // 4. perform CrHash to break the correlation if cot flag is false
      if (!cot) {
        ParaCrHashInplace_128(absl::MakeSpan(V[s]));
        ParaCrHashInplace_128(absl::MakeSpan(V_xor_delta[s]));
      }

      for (uint64_t j = 0; j < kBatchSize; ++j) {
        send_blocks[t * super_batch_size + s * kBatchSize + j][0] = V[s][j];
        send_blocks[t * super_batch_size + s * kBatchSize + j][1] =
            V_xor_delta[s][j];
      }
    }
  }

  // deal with normal batch
  for (uint64_t t = 0; t < batch_num; ++t) {
    // The same as IKNP OTe
    // 1. receive the masked choices
    auto recv_buff = ctx->Recv(ctx->NextRank(), "softspoken_switch_u");
    auto recv_U = absl::MakeSpan(static_cast<uint128_t*>(recv_buff.data()),
                                 recv_buff.size() / sizeof(uint128_t));
    YACL_ENFORCE(recv_U.size() == pprf_num_);

    // 2. smallfield/subspace VOLE
    GenSfVole(absl::MakeSpan(hash_buff), absl::MakeSpan(xor_buff),
              absl::MakeSpan(recv_U), absl::MakeSpan(V[t]));
    if (mal_) {
      allV[super_batch_num * step + t] = V[t];
    }

    // 3. Matrix Transpose
    if (numOt > batch_offset + t * kBatchSize) {
      MatrixTranspose128(&V[t]);
      XorBlock(absl::MakeSpan(V[t]), absl::MakeSpan(V_xor_delta[t]), delta);
      // 4. perform CrHash to break the correlation if cot flag is false
      if (!cot) {
        ParaCrHashInplace_128(absl::MakeSpan(V[t]));
        ParaCrHashInplace_128(absl::MakeSpan(V_xor_delta[t]));
      }

      const uint64_t limit =
          std::min(kBatchSize, numOt - batch_offset - t * kBatchSize);
      for (uint64_t j = 0; j < limit; ++j) {
        send_blocks[batch_offset + t * kBatchSize + j][0] = V[t][j];
        send_blocks[batch_offset + t * kBatchSize + j][1] = V_xor_delta[t][j];
      }
    }
  }

  if (mal_) {
    // Sender generates a random seed and sends it to receiver.
    uint128_t seed = SyncSeedSend(ctx);

    // Consistency check
    std::vector<uint64_t> rand_samples(all_batch_num * 2);
    PrgAesCtr(seed, absl::Span<uint64_t>(rand_samples));

    CheckMsg<uint128_t> check_msgs;
    for (size_t i = 0; i < all_batch_num; ++i) {
      for (size_t k = 0; k < kKappa; ++k) {
        check_msgs.t[k] ^= ClMul64(
            absl::MakeSpan(rand_samples.data() + i * 2, 2),
            absl::MakeSpan(reinterpret_cast<uint64_t*>(allV[i].data() + k), 2));
      }
    }

    CheckMsg msgs;
    std::array<uint64_t, kKappa> check_vals;
    for (size_t k = 0; k < kKappa; ++k) {
      check_vals[k] = Reduce64(check_msgs.t[k]);
    }

    msgs.Unpack(ctx->Recv(ctx->NextRank(), fmt::format("MAL-SS-CHECK-FINAL")));

    for (size_t k = 0; k < kKappa; ++k) {
      auto recv_check_val = msgs.t[k] ^ (p_idx_mask_[k] & msgs.x);
      YACL_ENFORCE(recv_check_val == check_vals[k]);
    }
  }
}

// old style interface
void SoftspokenOtExtReceiver::Recv(const std::shared_ptr<link::Context>& ctx,
                                   const dynamic_bitset<uint128_t>& choices,
                                   absl::Span<uint128_t> recv_blocks,
                                   bool cot) {
  if (!inited_) {
    OneTimeSetup(ctx);
  }

  YACL_ENFORCE(choices.size() == recv_blocks.size());
  const uint64_t& step = step_;
  const uint64_t batch_size = kBatchSize;
  const uint64_t super_batch_size = step * batch_size;
  const uint64_t numOt = recv_blocks.size();
  const uint64_t expand_numOt =
      (numOt + kS + kBatchSize - 1) / kBatchSize * kBatchSize;
  const uint64_t super_batch_num = numOt / super_batch_size;
  const uint64_t batch_offset = super_batch_num * super_batch_size;
  const uint64_t batch_num =
      (expand_numOt - batch_offset + kBatchSize - 1) / kBatchSize;
  const uint64_t all_batch_num = super_batch_num * step + batch_num;
  YACL_ENFORCE(all_batch_num * kBatchSize == expand_numOt);

  UninitAlignedVector<std::array<uint128_t, kKappa>, 32> allW(all_batch_num);
  auto choice_ext = ExtendChoice(choices, expand_numOt);
  // AVX need to be aligned to 32 bytes.
  // Extra one array for consitency check in batch_num for-loop.
  UninitAlignedVector<std::array<uint128_t, kKappa>, 32> W(step + 1);
  // AES Buffer & Xor Buffer to perform AES/PRG and XorReduce
  auto xor_buff = UninitAlignedVector<uint128_t>(pprf_num_ * pprf_range_, 0);
  UninitAlignedVector<uint128_t> U(pprf_num_ * step);

  // deal with super batch
  for (uint64_t t = 0; t < super_batch_num; ++t) {
    // The same as IKNP OTe, see `yacl/crypto/primitive/ot/iknp_ote_cc`
    // 1. smallfield/subspace VOLE
    for (uint64_t s = 0; s < step; ++s) {
      GenSfVole(choice_ext.data()[t * step + s], absl::MakeSpan(xor_buff),
                absl::MakeSpan(U.data() + s * pprf_num_, pprf_num_),
                absl::MakeSpan(W[s]));
      if (mal_) {
        allW[t * step + s] = W[s];
      }
    }
    // 2. send the masked choices
    ctx->SendAsync(ctx->NextRank(),
                   ByteContainerView(U.data(), U.size() * sizeof(uint128_t)),
                   "softspoken_switch_u");
    for (uint64_t s = 0; s < step; ++s) {
      // 3. matrix transpose
      MatrixTranspose128(&W[s]);
      // 4. perform CrHash to break the correlation if cot flag is false
      if (!cot) {
        ParaCrHashInplace_128(absl::MakeSpan(W[s]));
      }
      for (uint64_t j = 0; j < kBatchSize; ++j) {
        recv_blocks[t * super_batch_size + s * batch_size + j] = W[s][j];
      }
    }
  }

  // deal with normal bathc
  for (uint64_t t = 0; t < batch_num; ++t) {
    // The same as IKNP OTe
    // 1. smallfield/subspace VOLE
    GenSfVole(choice_ext.data()[super_batch_num * step + t],
              absl::MakeSpan(xor_buff), absl::MakeSpan(U),
              absl::MakeSpan(W[t]));
    if (mal_) {
      allW[super_batch_num * step + t] = W[t];
    }
    // 2. send the masked choices
    ctx->SendAsync(ctx->NextRank(),
                   ByteContainerView(U.data(), pprf_num_ * sizeof(uint128_t)),
                   "softspoken_switch_u");

    // 3. matrix transpose
    if (numOt > batch_offset + t * kBatchSize) {
      MatrixTranspose128(&W[t]);
      const uint64_t limit =
          std::min(kBatchSize, numOt - batch_offset - t * kBatchSize);
      // 4. perform CrHash to break the correlation if cot flag is false
      if (!cot) {
        ParaCrHashInplace_128(absl::MakeSpan(W[t]));
      }
      for (uint64_t j = 0; j < limit; ++j) {
        recv_blocks[batch_offset + t * kBatchSize + j] = W[t][j];
      }
    }
  }

  if (mal_) {
    // Recevies the random seed from sender
    uint128_t seed = SyncSeedRecv(ctx);

    // Consistency check
    std::vector<uint64_t> rand_samples(all_batch_num * 2);
    PrgAesCtr(seed, absl::Span<uint64_t>(rand_samples));

    CheckMsg<uint128_t> check_msgs;
    auto choice_span = absl::MakeSpan(
        reinterpret_cast<uint64_t*>(choice_ext.data()), all_batch_num * 2);
    check_msgs.x ^= ClMul64(absl::MakeSpan(rand_samples), choice_span);

    for (size_t i = 0; i < all_batch_num; ++i) {
      for (size_t k = 0; k < kKappa; ++k) {
        check_msgs.t[k] ^= ClMul64(
            absl::MakeSpan(rand_samples.data() + i * 2, 2),
            absl::MakeSpan(reinterpret_cast<uint64_t*>(allW[i].data() + k), 2));
      }
    }

    CheckMsg msgs;
    msgs.x = Reduce64(check_msgs.x);
    for (size_t k = 0; k < kKappa; ++k) {
      msgs.t[k] = Reduce64(check_msgs.t[k]);
    }
    auto buf = msgs.Pack();
    ctx->SendAsync(ctx->NextRank(), buf, fmt::format("MAL-SS-CHECK-FINAL"));
  }
}

}  // namespace yacl::crypto
