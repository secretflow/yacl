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

#include "yacl/kernel/algorithms/kos_ote.h"

#include <algorithm>
#include <array>
#include <utility>
#include <vector>

#include "yacl/base/byte_container_view.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/tools/common.h"
#include "yacl/math/f2k/f2k.h"
#include "yacl/utils/matrix_utils.h"
#include "yacl/utils/serialize.h"

namespace yacl::crypto {

namespace {

// For convenience, we use 128 bit computational security parameter and 64 bit
// statistical security parameter
constexpr size_t kKappa = YACL_MODULE_SECPARAM_C_UINT("kos_ote");
constexpr size_t kS = YACL_MODULE_SECPARAM_S_UINT("kos_ote");
constexpr size_t kBatchSize = 128;

struct CheckMsg {
  uint64_t x = 0;
  std::array<uint64_t, kKappa> t{0};

  // pack the check_msg into one byte buffer (for networking)
  Buffer Pack() {
    Buffer out((kKappa + 1) * sizeof(uint64_t));
    memcpy(out.data<uint8_t>(), &x, sizeof(uint64_t));
    memcpy(out.data<uint8_t>() + sizeof(uint64_t), t.data(),
           sizeof(uint64_t) * kKappa);
    return out;
  }

  // unpack the check_msg from byte buffer (for networking)
  void Unpack(ByteContainerView buf) {
    std::memcpy(&x, buf.data(), sizeof(uint64_t));
    std::memcpy(t.data(), buf.data() + sizeof(uint64_t),
                kKappa * sizeof(uint64_t));
  }
};

inline std::vector<uint128_t> VecXorMonochrome(absl::Span<const uint128_t> in,
                                               uint128_t block) {
  std::vector<uint128_t> res(in.size());
  for (size_t i = 0; i < in.size(); i++) {
    res[i] = in[i] ^ block;
  }
  return res;
}

inline std::pair<std::array<std::vector<uint128_t>, kKappa>,
                 std::array<std::vector<uint128_t>, kKappa>>
ExtendBaseOt(const OtSendStore& base_ot, size_t block_num) {
  std::array<std::vector<uint128_t>, kKappa> base_ot_ext0;
  std::array<std::vector<uint128_t>, kKappa> base_ot_ext1;
  for (size_t k = 0; k < base_ot.Size(); ++k) {
    base_ot_ext0[k].resize(block_num);
    base_ot_ext1[k].resize(block_num);
    PrgAesCtr(base_ot.GetBlock(k, 0), absl::Span<uint128_t>(base_ot_ext0[k]));
    PrgAesCtr(base_ot.GetBlock(k, 1), absl::Span<uint128_t>(base_ot_ext1[k]));
  }
  return std::make_pair(base_ot_ext0, base_ot_ext1);
}

inline std::array<std::vector<uint128_t>, kKappa> ExtendBaseOt(
    const OtRecvStore& base_ot, size_t block_num) {
  std::array<std::vector<uint128_t>, kKappa> base_ot_ext;
  for (size_t k = 0; k < base_ot.Size(); ++k) {
    base_ot_ext[k].resize(block_num);
    PrgAesCtr(base_ot.GetBlock(k), absl::Span<uint128_t>(base_ot_ext[k]));
  }
  return base_ot_ext;
}

inline dynamic_bitset<uint128_t> ExtendChoice(
    const dynamic_bitset<uint128_t>& choices, size_t final_size) {
  // Extend choices to batch_num * kBlockNum bits
  // 1st part (valid_ot_num bits): original ot choices
  // 2nd part (verify_ot_num bits): rand bits used for checking
  // 3rd part (the rest bits): padding 0;
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

}  // namespace

void KosOtExtSend(const std::shared_ptr<link::Context>& ctx,
                  const OtRecvStore& base_ot,
                  absl::Span<std::array<uint128_t, 2>> send_blocks, bool cot) {
  static_assert(kS == 64,
                "Currently, KOS only support statistical "
                "security = 64 bit");
  YACL_ENFORCE(ctx->WorldSize() == 2);
  YACL_ENFORCE(base_ot.Size() == kKappa);
  YACL_ENFORCE(!send_blocks.empty());

  const size_t ot_num_valid = send_blocks.size();
  const size_t ot_num_ext = ot_num_valid + kS;  // without batch padding
  const size_t batch_num = (ot_num_ext + kBatchSize - 1) / kBatchSize;
  const size_t block_num = batch_num * kBatchSize / 128;

  // Prepare for batched computation
  std::vector<uint128_t> q_ext(ot_num_ext);
  auto ot_ext = ExtendBaseOt(base_ot, block_num);

  // Note the following is identical to the IKNP protocol without the final hash
  // code partically copied from yacl/crypto-primitives/ot/extension/kkrt_ote.cc
  // For every batch
  for (size_t i = 0; i < batch_num; ++i) {
    // std::array<uint128_t, kBatchSize> recv_msg;
    const size_t offset = i * kBatchSize / 128;  // block offsets

    auto buf = ctx->Recv(ctx->NextRank(), fmt::format("KOS:{}", i));
    auto recv_msg = absl::MakeSpan(reinterpret_cast<uint128_t*>(buf.data()),
                                   buf.size() / sizeof(uint128_t));
    // Q = (u & s) ^ G(K_s) = ((G(K_0) ^ G(K_1) ^ r)) & s) ^ G(K_s)
    // Q = G(K_0) when s is 0
    // Q = G(K_0) ^ r when s is 1
    // Hence we get the wanted behavior in IKNP, that is:
    //  s == 0, the sender receives T = G(K_0)
    //  s == 1, the sender receives U = G(K_0) ^ r = T ^ r
    for (size_t k = 0; k < kKappa; ++k) {
      if (base_ot.GetChoice(k)) {
        ot_ext[k][offset] ^= recv_msg[k];
      }
    }
  }

  // Prepare for consistency check
  std::array<uint64_t, kKappa> q_check{0};

  // Sender generates a random seed and sends it to receiver.
  uint128_t seed = SyncSeedSend(ctx);
  // Generate the coefficent for consistency check
  std::vector<uint64_t> rand_samples(batch_num * 2);
  PrgAesCtr(seed, absl::MakeSpan(rand_samples));
  // =================== CONSISTENCY CHECK ===================
  for (size_t k = 0; k < kKappa; ++k) {
    auto k_msg_span = absl::MakeSpan(
        reinterpret_cast<uint64_t*>(ot_ext[k].data()), 2 * batch_num);
    q_check[k] = GfMul64(absl::MakeSpan(rand_samples), k_msg_span);
  }

  CheckMsg check_msgs;
  check_msgs.Unpack(ctx->Recv(ctx->NextRank(), fmt::format("KOS-CHECK")));

  for (size_t k = 0; k < kKappa; ++k) {
    uint128_t result = 0;
    if (base_ot.GetChoice(k)) {
      result = check_msgs.t[k] ^ (check_msgs.x);
    } else {
      result = check_msgs.t[k];
    }
    YACL_ENFORCE(result == q_check[k]);
  }
  // =================== CONSISTENCY CHECK ===================

  for (size_t i = 0; i < batch_num; ++i) {
    // AVX need to be aligned to 32 bytes.
    alignas(32) std::array<uint128_t, kBatchSize> recv_msg;
    const size_t offset = i * kBatchSize / 128;  // block offsets

    for (size_t k = 0; k < kKappa; ++k) {
      const auto& ot_slice = ot_ext[k][offset];
      recv_msg[k] = ot_slice;
    }

    MatrixTranspose128(&recv_msg);

    // Finalize(without crhash)
    const size_t limit = std::min(kBatchSize, ot_num_ext - i * kBatchSize);
    for (size_t j = 0; j < limit; ++j) {
      q_ext[i * kBatchSize + j] = recv_msg[j];
    }
  }

  uint128_t delta = static_cast<uint128_t>(*base_ot.CopyChoice().data());
  q_ext.resize(ot_num_valid);
  auto& batch0 = q_ext;
  auto batch1 = VecXorMonochrome(absl::MakeSpan(q_ext), delta);

  if (!cot) {
    ParaCrHashInplace_128(absl::MakeSpan(batch0));
    ParaCrHashInplace_128(absl::MakeSpan(batch1));
  }

  for (size_t i = 0; i < ot_num_valid; i++) {
    send_blocks[i][0] = batch0[i];
    send_blocks[i][1] = batch1[i];
  }
}

void KosOtExtRecv(const std::shared_ptr<link::Context>& ctx,
                  const OtSendStore& base_ot,
                  const dynamic_bitset<uint128_t>& choices,
                  absl::Span<uint128_t> recv_blocks, bool cot) {
  static_assert(kS == 64,
                "Currently, KOS only support statistical "
                "security = 64 bit");
  YACL_ENFORCE(ctx->WorldSize() == 2);     // Check OT has two parties
  YACL_ENFORCE(base_ot.Size() == kKappa);  // Check base OT size
  YACL_ENFORCE(recv_blocks.size() == choices.size());
  YACL_ENFORCE(!recv_blocks.empty());

  const size_t ot_num_valid = recv_blocks.size();
  const size_t ot_num_ext = ot_num_valid + kS;  // without batch padding
  const size_t batch_num = (ot_num_ext + kBatchSize - 1) / kBatchSize;
  const size_t block_num = batch_num * kBatchSize / 128;

  // Prepare for batched computation
  std::vector<uint128_t> t_ext(ot_num_ext);
  auto choice_ext = ExtendChoice(choices, batch_num * kBatchSize);
  auto ot_ext = ExtendBaseOt(base_ot, block_num);

  // Note the following is identical to the IKNP protocol without the final
  // hash code partically copied from
  // yacl/crypto-primitives/ot/extension/kkrt_ote.cc For a task of
  // generating 129 OTs, we actually generates 128 * 2 = 256 OTs.
  for (size_t i = 0; i < batch_num; ++i) {
    const size_t offset = i * kBatchSize / 128;  // block offsets
    uint128_t choice_slice = *(choice_ext.data() + offset);
    std::array<uint128_t, kKappa> send_msg;
    for (size_t k = 0; k < kKappa; ++k) {
      const auto& ot_slice0 = ot_ext.first[k][offset];
      const auto& ot_slice1 = ot_ext.second[k][offset];
      send_msg[k] = ot_slice0 ^ ot_slice1 ^ choice_slice;
    }
    ctx->SendAsync(
        ctx->NextRank(),
        ByteContainerView(send_msg.data(), send_msg.size() * sizeof(uint128_t)),
        fmt::format("KOS:{}", i));
  }

  // Prepare for consistency check
  CheckMsg check_msgs;

  // Recevies the random seed from sender
  uint128_t seed = SyncSeedRecv(ctx);
  // Generate coefficent for consistency check
  std::vector<uint64_t> rand_samples(batch_num * 2);
  PrgAesCtr(seed, absl::Span<uint64_t>(rand_samples));

  // =================== CONSISTENCY CHECK ===================
  auto choice_span = absl::MakeSpan(
      reinterpret_cast<uint64_t*>(choice_ext.data()), batch_num * 2);
  check_msgs.x = GfMul64(absl::MakeSpan(rand_samples), choice_span);

  for (size_t k = 0; k < kKappa; ++k) {
    check_msgs.t[k] = GfMul64(
        absl::MakeSpan(rand_samples),
        absl::MakeSpan(reinterpret_cast<uint64_t*>(ot_ext.first[k].data()),
                       batch_num * 2));
  }

  auto buf = check_msgs.Pack();
  ctx->SendAsync(ctx->NextRank(), buf, fmt::format("KOS-CHECK"));
  // =================== CONSISTENCY CHECK ===================

  for (size_t i = 0; i < batch_num; ++i) {
    // AVX need to be aligned to 32 bytes.
    alignas(32) std::array<uint128_t, kKappa> t;
    const size_t offset = i * kBatchSize / 128;  // block offsets
    for (size_t k = 0; k < kKappa; ++k) {
      t[k] = ot_ext.first[k][offset];
    }

    // Transpose.
    MatrixTranspose128(&t);

    // Finalize (without crhash)
    const size_t limit = std::min(kBatchSize, ot_num_ext - i * kBatchSize);
    for (size_t j = 0; j < limit; ++j) {
      t_ext[i * kBatchSize + j] = t[j];
    }
  }

  t_ext.resize(ot_num_valid);
  if (!cot) {
    ParaCrHashInplace_128(absl::MakeSpan(t_ext));
  }
  for (size_t i = 0; i < ot_num_valid; i++) {
    recv_blocks[i] = t_ext[i];
  }
}
}  // namespace yacl::crypto
