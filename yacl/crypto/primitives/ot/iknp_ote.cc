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

#include "yacl/crypto/primitives/ot/iknp_ote.h"

#include <algorithm>
#include <memory>
#include <vector>

#include "yacl/base/byte_container_view.h"
#include "yacl/base/exception.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/tools/prg.h"
#include "yacl/crypto/tools/random_permutation.h"
#include "yacl/utils/matrix_utils.h"

namespace yacl::crypto {

namespace {

constexpr size_t kBatchSize = 128;
constexpr size_t kKappa = 128;

inline std::array<uint128_t, kBatchSize> XorBatchedBlock(
    const absl::Span<uint128_t> in, const uint128_t block) {
  std::array<uint128_t, kBatchSize> res;
  for (size_t i = 0; i < in.size(); i++) {
    res[i] = in[i] ^ block;
  }
  return res;
}

}  // namespace

void IknpOtExtSend(const std::shared_ptr<link::Context>& ctx,
                   const std::shared_ptr<OtRecvStore>& base_ot,
                   absl::Span<std::array<uint128_t, 2>> send_blocks,
                   const bool cot) {
  YACL_ENFORCE(ctx->WorldSize() == 2);
  YACL_ENFORCE(base_ot->Size() == kKappa);
  YACL_ENFORCE(!send_blocks.empty());
  YACL_ENFORCE(!base_ot->IsSliced());

  const size_t batch_num = (send_blocks.size() + kBatchSize - 1) / kBatchSize;
  const size_t block_num = batch_num * kBatchSize / 128;

  // Prepare full-size ts
  std::array<std::vector<uint128_t>, kKappa> ts;  // stores for all
                                                  // randomness

  // Generate all the psedo-randomness to kKappa * kOtNum
  for (size_t k = 0; k < kKappa; ++k) {
    ts[k].resize(block_num);
    PrgAesCtr<uint128_t>(base_ot->GetBlock(k), absl::MakeSpan(ts[k]));
  }

  // For every batch
  for (size_t i = 0; i < block_num; ++i) {
    const size_t batch_offset = i * kBatchSize / 128;  // in num of blocks

    std::array<uint128_t, kBatchSize> batch0;
    std::array<uint128_t, kBatchSize> batch1;
    auto buf = ctx->Recv(ctx->NextRank(), fmt::format("IKNP:{}", i));
    std::memcpy(batch0.data(), buf.data(), buf.size());

    // Q = (u & s) ^ G(K_s) = ((G(K_0) ^ G(K_1) ^ r)) & s) ^ G(K_s)
    // Q = G(K_0) when s is 0
    // Q = G(K_0) ^ r when s is 1
    // Hence we get the wanted behavior in IKNP, that is:
    //  s == 0, the sender receives T = G(K_0)
    //  s == 1, the sender receives U = G(K_0) ^ r = T ^ r
    for (size_t k = 0; k < kKappa; ++k) {
      if (base_ot->GetChoice(k)) {
        batch0[k] ^= ts[k][batch_offset];
      } else {
        batch0[k] = ts[k][batch_offset];
      }
    }

    // Transpose.
    SseTranspose128(&batch0);

    auto tmp_choice = base_ot->CopyChoice();
    batch1 = XorBatchedBlock(absl::MakeSpan(batch0),
                             static_cast<uint128_t>(*tmp_choice.data()));

    if (!cot) {
      ParaCrHashInplace_128(absl::MakeSpan(batch0));
      ParaCrHashInplace_128(absl::MakeSpan(batch1));
    }

    // Build Q & Q^S
    // Break correlation.
    const size_t limit =
        std::min(kBatchSize, send_blocks.size() - i * kBatchSize);

    for (size_t j = 0; j < limit; ++j) {
      send_blocks[i * kBatchSize + j][0] = batch0[j];
      send_blocks[i * kBatchSize + j][1] = batch1[j];
    }
  }
}

void IknpOtExtRecv(const std::shared_ptr<link::Context>& ctx,
                   const std::shared_ptr<OtSendStore>& base_ot,
                   const dynamic_bitset<uint128_t>& choices,
                   absl::Span<uint128_t> recv_blocks, const bool cot) {
  YACL_ENFORCE(ctx->WorldSize() == 2);  // Make sure that OT has two parties
  YACL_ENFORCE(base_ot->Size() == kKappa);
  YACL_ENFORCE(recv_blocks.size() == choices.size());
  YACL_ENFORCE(!recv_blocks.empty());
  YACL_ENFORCE(!base_ot->IsSliced());

  const size_t batch_num = (recv_blocks.size() + kBatchSize - 1) / kBatchSize;
  const size_t block_num = batch_num * kBatchSize / 128;
  auto choices_copy = choices;

  std::array<std::vector<uint128_t>, kKappa> t0;
  std::array<std::vector<uint128_t>, kKappa> t1;

  for (size_t k = 0; k < kKappa; ++k) {
    t0[k].resize(block_num);
    t1[k].resize(block_num);
    PrgAesCtr<uint128_t>(base_ot->GetBlock(k, 0), absl::MakeSpan(t0[k]));
    PrgAesCtr<uint128_t>(base_ot->GetBlock(k, 1), absl::MakeSpan(t1[k]));
  }

  // append to kBatchNum * kBatchSize
  choices_copy.resize(batch_num * kBatchSize);

  // For a task of generating 129 OTs, we actually generates 128 * 2 = 256
  // OTs.

  for (size_t i = 0; i < batch_num; ++i) {
    const size_t batch_offset = i * kBatchSize / 128;  // in num of blocks

    // get the choices for this batch
    uint128_t batch_choice = *(choices_copy.data() + i);

    std::array<uint128_t, kKappa> batch_data;
    std::array<uint128_t, kKappa> batch;
    // const auto* batch_ptr = recv_blocks.data() + i * kBatchSize;

    for (size_t k = 0; k < kKappa; ++k) {
      // Build u = G(K_0) ^ G(K_1) ^ r
      batch_data[k] = t0[k][batch_offset] ^ t1[k][batch_offset] ^ batch_choice;

      // t = G(K_0)
      batch[k] = t0[k][batch_offset];
    }

    // working_bits =   <block1>    ...     <block2>    ...   <blockn>
    // size =         (kBatchSize)        (kBatchSize)      (kBatchSize)
    ctx->SendAsync(ctx->NextRank(),
                   ByteContainerView(batch_data.data(),
                                     batch_data.size() * sizeof(uint128_t)),
                   fmt::format("IKNP:{}", i));

    // Transpose.
    SseTranspose128(&batch);
    // NaiveTranspose(&t);

    // Break correlation.
    // Output t0 as recv_block.
    const size_t limit =
        std::min(kBatchSize, recv_blocks.size() - i * kBatchSize);

    if (!cot) {
      ParaCrHashInplace_128(absl::MakeSpan(batch));
    }
    for (size_t j = 0; j < limit; ++j) {
      recv_blocks[i * kBatchSize + j] = batch[j];
    }
  }
}

}  // namespace yacl::crypto
