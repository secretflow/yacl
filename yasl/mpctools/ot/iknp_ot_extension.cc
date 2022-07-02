#include "yasl/mpctools/ot/iknp_ot_extension.h"

#include <sys/types.h>

#include <chrono>
#include <cstddef>
#include <random>

#include "yasl/base/byte_container_view.h"
#include "yasl/base/exception.h"
#include "yasl/base/int128.h"
#include "yasl/crypto/pseudo_random_generator.h"
#include "yasl/crypto/random_oracle.h"
#include "yasl/crypto/utils.h"
#include "yasl/mpctools/ot/utils.h"

namespace yasl {
namespace {

constexpr size_t kBatchSize = 128;
constexpr size_t kKappa = 128;
constexpr uint128_t kAllOneMask = uint128_t(-1);

}  // namespace

void IknpOtExtSend(const std::shared_ptr<link::Context>& ctx,
                   const BaseRecvOptions& base_options,
                   absl::Span<std::array<uint128_t, 2>> send_blocks) {
  YASL_ENFORCE(ctx->WorldSize() == 2);
  YASL_ENFORCE(base_options.choices.size() == base_options.blocks.size());
  // k == 128, can be extended to any |l| >= k by AES encryption.
  YASL_ENFORCE(base_options.choices.size() == kKappa);
  YASL_ENFORCE(!send_blocks.empty());

  std::vector<PseudoRandomGenerator<uint128_t>> prgs;
  for (size_t s = 0; s < kKappa; ++s) {
    prgs.emplace_back(base_options.blocks[s]);
  }

  // Build S = choice_mask.
  uint128_t choice_mask = 0;
  for (size_t i = 0; i < base_options.choices.size(); i++) {
    choice_mask |= base_options.choices[i] ? (uint128_t(1) << i) : uint128_t(0);
  }

  const size_t kNumBatch = (send_blocks.size() + kBatchSize - 1) / kBatchSize;

  for (size_t i = 0; i < kNumBatch; ++i) {
    std::array<uint128_t, kBatchSize> batch;
    auto buf = ctx->Recv(ctx->NextRank(), fmt::format("IKNP:{}", i));
    YASL_ENFORCE(buf.size() == batch.size() * sizeof(uint128_t));
    std::memcpy(batch.data(), buf.data(), buf.size());
    // Q = (u & s) ^ G(K_s) = ((G(K_0) ^ G(K_1) ^ r)) & s) ^ G(K_s)
    // Q = G(K_0) when s is 0
    // Q = G(K_0) ^ r when s is 1
    // Hence we get the wanted behavior in IKNP, that is:
    //  s == 0, the sender receives T = G(K_0)
    //  s == 1, the sender receives U = G(K_0) ^ r = T ^ r
    for (size_t k = 0; k < kKappa; ++k) {
      const uint128_t s = base_options.choices[k] ? kAllOneMask : 0;
      const uint128_t gen_ks = prgs[k]();
      batch[k] &= s;
      batch[k] ^= gen_ks;
    }
    // Transpose.
    NaiveTranspose(&batch);
    // Build Q & Q^S
    // Break correlation.
    size_t limit = std::min(kBatchSize, send_blocks.size() - i * kBatchSize);
    for (size_t offset = 0; offset < limit; ++offset) {
      send_blocks[i * kBatchSize + offset][0] =
          RandomOracle::GetDefault().Gen(batch[offset]);
      send_blocks[i * kBatchSize + offset][1] =
          RandomOracle::GetDefault().Gen(batch[offset] ^ choice_mask);
    }
  }
}

void IknpOtExtRecv(const std::shared_ptr<link::Context>& ctx,
                   const BaseSendOptions& base_options,
                   absl::Span<const uint128_t> choices,
                   absl::Span<uint128_t> recv_blocks) {
  YASL_ENFORCE(ctx->WorldSize() == 2);
  // k == 128, can be extended to any |l| >= k by AES encryption.
  YASL_ENFORCE(base_options.blocks.size() == kKappa);
  YASL_ENFORCE(!recv_blocks.empty());

  std::vector<PseudoRandomGenerator<uint128_t>> prgs0;
  std::vector<PseudoRandomGenerator<uint128_t>> prgs1;
  for (size_t k = 0; k < kKappa; ++k) {
    // Build PRG from seed K0.
    prgs0.emplace_back(base_options.blocks[k][0]);
    // Build PRG from seed K1.
    prgs1.emplace_back(base_options.blocks[k][1]);
  }

  const size_t kNumBatch = (recv_blocks.size() + kBatchSize - 1) / kBatchSize;
  YASL_ENFORCE(choices.size() == kNumBatch);

  for (size_t i = 0; i < kNumBatch; ++i) {
    std::array<uint128_t, kBatchSize> batch;
    std::array<uint128_t, kBatchSize> t;
    for (size_t k = 0; k < kKappa; ++k) {
      // G(K_0)
      uint128_t gen_k0 = prgs0[k]();
      // G(K_1)
      uint128_t gen_k1 = prgs1[k]();
      // Build u = G(K_0) ^ G(K_1) ^ r
      batch[k] = gen_k0 ^ gen_k1 ^ choices[i];
      // t = G(K_0)
      t[k] = gen_k0;
    }
    ctx->SendAsync(
        ctx->NextRank(),
        ByteContainerView(reinterpret_cast<const std::byte*>(batch.data()),
                          batch.size() * sizeof(uint128_t)),
        fmt::format("IKNP:{}", i));
    // Transpose.
    NaiveTranspose(&t);
    // Break correlation.
    // Output t0 as recv_block.
    size_t limit = std::min(kBatchSize, recv_blocks.size() - i * kBatchSize);
    for (size_t offset = 0; offset < limit; ++offset) {
      recv_blocks[i * kBatchSize + offset] =
          RandomOracle::GetDefault().Gen(t[offset]);
    }
  }
}

}  // namespace yasl
