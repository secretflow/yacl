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

#include "yacl/kernel/algorithms/portable_ot_interface.h"

#include "simplest_ot_portable/ot_receiver.h"
#include "simplest_ot_portable/ot_sender.h"

#include "yacl/base/exception.h"
#include "yacl/crypto/tools/ro.h"

namespace yacl::crypto {

void PortableOtInterface::Recv(const std::shared_ptr<link::Context> &ctx,
                               const dynamic_bitset<uint128_t> &choices,
                               absl::Span<Block> recv_blocks) {
  const int kNumOt = choices.size();
  SIMPLEOT_RECEIVER receiver;

  // Wait for sender S_pack.
  auto buffer = ctx->Recv(ctx->NextRank(), "BASE_OT:S_PACK");
  YACL_ENFORCE_EQ(buffer.size(), static_cast<int64_t>(sizeof(receiver.S_pack)));
  std::memcpy(receiver.S_pack, buffer.data(), buffer.size());

  if (!portable_receiver_procS_check(&receiver)) {
    YACL_THROW("simplest-ot receiver_procS failed");
  }

  const auto &RO = RandomOracle::GetDefault();
  std::vector<std::array<unsigned char, PACKBYTES>> send_msgs(kNumOt);

  for (int i = 0; i < kNumOt; i++) {
    const int batch_size = std::min(1, kNumOt - i);

    unsigned char messages[1][HASHBYTES];
    auto *rs_pack = reinterpret_cast<unsigned char *>(send_msgs[i].data());
    unsigned char batch_choices[1] = {0};

    for (int j = 0; j < batch_size; j++) {
      batch_choices[j] = choices[i + j] ? 1 : 0;
    }

    portable_receiver_rsgen(&receiver, rs_pack, batch_choices);

    portable_receiver_keygen(&receiver, &messages[0]);
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
                 ByteContainerView(send_msgs.data(), kNumOt * PACKBYTES),
                 fmt::format("BASE_OT:RS_PACK"));
}

void PortableOtInterface::Send(const std::shared_ptr<link::Context> &ctx,
                               absl::Span<std::array<Block, 2>> send_blocks) {
  const int kNumOt = send_blocks.size();
  SIMPLEOT_SENDER sender;

  // Send S_pack.
  unsigned char S_pack[PACKBYTES];
  portable_sender_genS(&sender, S_pack);
  ctx->SendAsync(ctx->NextRank(), S_pack, "BASE_OT:S_PACK");

  const auto &RO = RandomOracle::GetDefault();
  auto buffer = ctx->Recv(ctx->NextRank(), fmt::format("BASE_OT:RS_PACK"));
  YACL_ENFORCE_EQ(buffer.size(), static_cast<int64_t>(kNumOt * PACKBYTES));

  for (int i = 0; i < kNumOt; i++) {
    const int batch_size = std::min(1, kNumOt - i);

    auto *rs_pack =
        reinterpret_cast<unsigned char *>(buffer.data()) + i * PACKBYTES;
    unsigned char messages[2][1][HASHBYTES];

    if (!portable_sender_keygen_check(&sender, rs_pack, messages)) {
      YACL_THROW("simplest-ot: sender_keygen failed");
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
      ByteContainerView buf0(&messages[0][j][0], sizeof(uint128_t));
      ByteContainerView buf1(&messages[1][j][0], sizeof(uint128_t));

      send_blocks[i + j][0] = RO.Gen<uint128_t>(buf0, i + j);
      send_blocks[i + j][1] = RO.Gen<uint128_t>(buf1, i + j);
    }
  }
}

}  // namespace yacl::crypto
