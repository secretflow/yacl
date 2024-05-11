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

#include "yacl/kernel/algorithms/x86_asm_ot_interface.h"

#include <algorithm>
#include <memory>
#include <vector>

#include "simplest_ot_x86_asm/ot_receiver.h"
#include "simplest_ot_x86_asm/ot_sender.h"

#include "yacl/base/byte_container_view.h"
#include "yacl/base/exception.h"
#include "yacl/crypto/tools/ro.h"
#include "yacl/math/gadget.h"

namespace yacl::crypto {

void X86AsmOtInterface::Recv(const std::shared_ptr<link::Context> &ctx,
                             const dynamic_bitset<uint128_t> &choices,
                             absl::Span<Block> recv_blocks) {
  const int kNumOt = choices.size();
  auto receiver = std::make_unique<SIMPLEOT_RECEIVER>();

  // Wait for sender S_pack.
  auto buffer = ctx->Recv(ctx->NextRank(), "BASE_OT:S_PACK");
  YACL_ENFORCE_EQ(buffer.size(),
                  static_cast<int64_t>(sizeof(receiver->S_pack)));
  std::memcpy(receiver->S_pack, buffer.data(), buffer.size());

  if (!receiver_procS_check(receiver.get())) {
    YACL_THROW("simplest-ot receiver_procS failed");
  }

  receiver_maketable(receiver.get());

  const auto &RO = RandomOracle::GetDefault();

  const auto batch_num = math::DivCeil(kNumOt, 4);
  std::vector<std::array<unsigned char, 4 * PACKBYTES>> send_msgs(batch_num);

  for (int i = 0; i < kNumOt; i += 4) {
    const int batch_size = std::min(4, kNumOt - i);

    unsigned char messages[4][HASHBYTES];
    auto *rs_pack = reinterpret_cast<unsigned char *>(send_msgs[i / 4].data());
    unsigned char batch_choices[4] = {0, 0, 0, 0};

    for (int j = 0; j < batch_size; j++) {
      batch_choices[j] = choices[i + j] ? 1 : 0;
    }

    receiver_rsgen(receiver.get(), rs_pack, batch_choices);

    receiver_keygen(receiver.get(), &messages[0]);
    for (int j = 0; j < batch_size; ++j) {
      static_assert(sizeof(recv_blocks[i]) <= HASHBYTES, "Illegal Block size.");
      std::memcpy(&recv_blocks[i + j], &messages[j][0],
                  sizeof(recv_blocks[i + j]));

      // even though there's already a hash in sender_keygen_check, we need to
      // hash again with the index i to ensure security
      // ref: https://eprint.iacr.org/2021/682
      ByteContainerView buf(&messages[j][0], sizeof(uint128_t));
      recv_blocks[i + j] = RO.Gen<uint128_t>(buf, i + j);
    }
  }

  ctx->SendAsync(ctx->NextRank(),
                 ByteContainerView(send_msgs.data(), batch_num * 4 * PACKBYTES),
                 fmt::format("BASE_OT:RS_PACK"));
}

void X86AsmOtInterface::Send(const std::shared_ptr<link::Context> &ctx,
                             absl::Span<std::array<Block, 2>> send_blocks) {
  const int kNumOt = send_blocks.size();
  auto sender = std::make_unique<SIMPLEOT_SENDER>();

  // Send S_pack.
  unsigned char S_pack[PACKBYTES];
  sender_genS(sender.get(), S_pack);
  ctx->SendAsync(ctx->NextRank(), S_pack, "BASE_OT:S_PACK");

  const auto batch_num = math::DivCeil(kNumOt, 4);
  // Receiver rs_pack
  auto buffer = ctx->Recv(ctx->NextRank(), fmt::format("BASE_OT:RS_PACK"));
  YACL_ENFORCE_EQ(buffer.size(),
                  static_cast<int64_t>(batch_num * 4 * PACKBYTES));

  for (int i = 0; i < kNumOt; i += 4) {
    const int batch_size = std::min(4, kNumOt - i);

    // unsigned char rs_pack[4 * PACKBYTES];
    auto *rs_pack =
        reinterpret_cast<unsigned char *>(buffer.data()) + i * PACKBYTES;
    unsigned char messages[2][4][HASHBYTES];

    if (!sender_keygen_check(sender.get(), rs_pack, messages)) {
      YACL_THROW("simplest-ot: sender_keygen failed");
    }

    const auto &RO = RandomOracle::GetDefault();

    for (int j = 0; j < batch_size; ++j) {
      static_assert(sizeof(send_blocks[0][0]) <= HASHBYTES,
                    "Illegal Block size.");

      // even though there's already a hash in sender_keygen_check, we need to
      // hash again with the index i to ensure security
      // ref: https://eprint.iacr.org/2021/682
      ByteContainerView buf0(&messages[0][j][0], sizeof(uint128_t));
      ByteContainerView buf1(&messages[1][j][0], sizeof(uint128_t));

      send_blocks[i + j][0] = RO.Gen<uint128_t>(buf0, i + j);
      send_blocks[i + j][1] = RO.Gen<uint128_t>(buf1, i + j);
    }
  }
}

}  // namespace yacl::crypto
