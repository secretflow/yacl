#include "yasl/mpctools/ot/portable_ot_interface.h"

#include "simplest_ot_portable/ot_receiver.h"
#include "simplest_ot_portable/ot_sender.h"

#include "yasl/base/exception.h"
#include "yasl/crypto/random_oracle.h"

namespace yasl {

void PortableOtInterface::Recv(const std::shared_ptr<link::Context> &ctx,
                               const std::vector<bool> &choices,
                               absl::Span<Block> recv_blocks) {
  const int kNumOt = choices.size();
  SIMPLEOT_RECEIVER receiver;

  // Wait for sender S_pack.
  auto buffer = ctx->Recv(ctx->NextRank(), "BASE_OT:S_PACK");
  YASL_ENFORCE_EQ(buffer.size(), static_cast<int64_t>(sizeof(receiver.S_pack)));
  std::memcpy(receiver.S_pack, buffer.data(), buffer.size());

  if (!portable_receiver_procS_check(&receiver)) {
    YASL_THROW("simplest-ot receiver_procS failed");
  }

  for (int i = 0; i < kNumOt; i++) {
    const int batch_size = std::min(1, kNumOt - i);

    unsigned char messages[1][HASHBYTES];
    unsigned char rs_pack[PACKBYTES];
    unsigned char batch_choices[1] = {0};

    for (int j = 0; j < batch_size; j++) {
      batch_choices[j] = choices[i + j] ? 1 : 0;
    }

    portable_receiver_rsgen(&receiver, rs_pack, batch_choices);
    ctx->Send(ctx->NextRank(), rs_pack, fmt::format("BASE_OT:{}", i));

    portable_receiver_keygen(&receiver, &messages[0]);
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

void PortableOtInterface::Send(const std::shared_ptr<link::Context> &ctx,
                               absl::Span<std::array<Block, 2>> send_blocks) {
  const int kNumOt = send_blocks.size();
  SIMPLEOT_SENDER sender;

  // Send S_pack.
  unsigned char S_pack[PACKBYTES];
  portable_sender_genS(&sender, S_pack);
  ctx->Send(ctx->NextRank(), S_pack, "BASE_OT:S_PACK");

  for (int i = 0; i < kNumOt; i++) {
    const int batch_size = std::min(1, kNumOt - i);

    unsigned char rs_pack[PACKBYTES];
    unsigned char messages[2][1][HASHBYTES];

    auto buffer = ctx->Recv(ctx->NextRank(), fmt::format("BASE_OT:{}", i));
    YASL_ENFORCE_EQ(buffer.size(), static_cast<int64_t>(sizeof(rs_pack)));
    std::memcpy(rs_pack, buffer.data(), buffer.size());
    if (!portable_sender_keygen_check(&sender, rs_pack, messages)) {
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
