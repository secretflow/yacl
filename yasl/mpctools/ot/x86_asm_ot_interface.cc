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


#include "yasl/mpctools/ot/x86_asm_ot_interface.h"

#include "simplest_ot_x86_asm/ot_receiver.h"
#include "simplest_ot_x86_asm/ot_sender.h"

#include "yasl/base/exception.h"
#include "yasl/crypto/random_oracle.h"

#include <memory>

namespace yasl {

void X86AsmOtInterface::Recv(const std::shared_ptr<link::Context> &ctx,
                             const std::vector<bool> &choices,
                             absl::Span<Block> recv_blocks) {
  const int kNumOt = choices.size();
  auto receiver = std::make_unique<SIMPLEOT_RECEIVER>();

  // Wait for sender S_pack.
  auto buffer = ctx->Recv(ctx->NextRank(), "BASE_OT:S_PACK");
  YASL_ENFORCE_EQ(buffer.size(), static_cast<int64_t>(sizeof(receiver->S_pack)));
  std::memcpy(receiver->S_pack, buffer.data(), buffer.size());

  if (!receiver_procS_check(receiver.get())) {
    YASL_THROW("simplest-ot receiver_procS failed");
  }

  receiver_maketable(receiver.get());

  for (int i = 0; i < kNumOt; i += 4) {
    const int batch_size = std::min(4, kNumOt - i);

    unsigned char messages[4][HASHBYTES];
    unsigned char rs_pack[4 * PACKBYTES];
    unsigned char batch_choices[4] = {0, 0, 0, 0};

    for (int j = 0; j < batch_size; j++) {
      batch_choices[j] = choices[i + j] ? 1 : 0;
    }

    receiver_rsgen(receiver.get(), rs_pack, batch_choices);
    ctx->Send(ctx->NextRank(), rs_pack, fmt::format("BASE_OT:{}", i));

    receiver_keygen(receiver.get(), &messages[0]);
    for (int j = 0; j < batch_size; ++j) {
      static_assert(sizeof(recv_blocks[i]) <= HASHBYTES, "Illegal Block size.");
      std::memcpy(&recv_blocks[i + j], &messages[j][0],
                  sizeof(recv_blocks[i + j]));

      // even though there's already a hash in sender_keygen_check, we need to
      // hash again with the index i to ensure security
      // ref: https://eprint.iacr.org/2021/682

      recv_blocks[i + j] = RandomOracle::GetDefault().Gen(
          recv_blocks[i + j] ^ (i + j));  // output size = 128 bit
    }
  }
}

void X86AsmOtInterface::Send(const std::shared_ptr<link::Context> &ctx,
                             absl::Span<std::array<Block, 2>> send_blocks) {
  const int kNumOt = send_blocks.size();
  auto sender = std::make_unique<SIMPLEOT_SENDER>();

  // Send S_pack.
  unsigned char S_pack[PACKBYTES];
  sender_genS(sender.get(), S_pack);
  ctx->Send(ctx->NextRank(), S_pack, "BASE_OT:S_PACK");

  for (int i = 0; i < kNumOt; i += 4) {
    const int batch_size = std::min(4, kNumOt - i);

    unsigned char rs_pack[4 * PACKBYTES];
    unsigned char messages[2][4][HASHBYTES];

    auto buffer = ctx->Recv(ctx->NextRank(), fmt::format("BASE_OT:{}", i));
    YASL_ENFORCE_EQ(buffer.size(), static_cast<int64_t>(sizeof(rs_pack)));
    std::memcpy(rs_pack, buffer.data(), static_cast<int64_t>(buffer.size()));
    if (!sender_keygen_check(sender.get(), rs_pack, messages)) {
      YASL_THROW("simplest-ot: sender_keygen failed");
    }

    for (int j = 0; j < batch_size; ++j) {
      static_assert(sizeof(send_blocks[0][0]) <= HASHBYTES,
                    "Illegal Block size.");

      std::memcpy(&send_blocks[i + j][0], &messages[0][j][0],
                  sizeof(send_blocks[i + j][0]));
      std::memcpy(&send_blocks[i + j][1], &messages[1][j][0],
                  sizeof(send_blocks[i + j][1]));

      // even though there's already a hash in sender_keygen_check, we need to
      // hash again with the index i to ensure security
      // ref: https://eprint.iacr.org/2021/682

      send_blocks[i + j][0] = RandomOracle::GetDefault().Gen(
          send_blocks[i + j][0] ^ (i + j));  // output size = 128 bit
      send_blocks[i + j][1] = RandomOracle::GetDefault().Gen(
          send_blocks[i + j][1] ^ (i + j));  // output size = 128 bit
    }
  }
}

}  // namespace yasl
