// Copyright 2024 Ant Group Co., Ltd.
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

#include "yacl/crypto/experimental/sync_drbg/sync_drbg.h"

#include "yacl/base/byte_container_view.h"

namespace yacl::crypto {

namespace {
constexpr size_t kBatchSize = 65536;

// Recall the following definition
//
// typedef struct hash_drbg_context {
//   const EVP_MD *md;                      /* public param */
//   unsigned char V[MAX_SEED_BYTE_LENGTH]; /* internal state */
//   unsigned char C[MAX_SEED_BYTE_LENGTH]; /* internal state */
//   unsigned int hash_output_len;          /* public param */
//   unsigned int security_strength;        /* public param */
//   unsigned int seed_byte_len;            /* public param */
//   long long reseed_counter;              /* internal state */
// } HASH_DRBG_CTX;
//
constexpr unsigned int kHashDrbgHashOutputLen = 32;
constexpr unsigned int kHashDrbgSecurityStrength = 128;
constexpr unsigned int kSeedByteLen = 55;  // 440 bits = 55 bytes

}  // namespace

SyncDrbg::SyncDrbg(const HashDrbgCtx& ctx) {  // copy
  ctx_->md = ctx->md;
  ctx_->hash_output_len = ctx->hash_output_len;
  ctx_->security_strength = ctx->security_strength;
  ctx_->reseed_counter = ctx->reseed_counter;
  ctx_->seed_byte_len = ctx->seed_byte_len;
  std::memcpy(ctx_->C, ctx->C, MAX_SEED_BYTE_LENGTH);
  std::memcpy(ctx_->V, ctx->V, MAX_SEED_BYTE_LENGTH);
}

Buffer SyncDrbg::serialize_hash_drbg_ctx() {
  Buffer out(MAX_SEED_BYTE_LENGTH * 2 + sizeof(long long));
  memcpy(out.data(), ctx_->V, MAX_SEED_BYTE_LENGTH);
  memcpy((unsigned char*)out.data() + MAX_SEED_BYTE_LENGTH, ctx_->C,
         MAX_SEED_BYTE_LENGTH);
  memcpy((unsigned char*)out.data() + 2 * MAX_SEED_BYTE_LENGTH,
         &ctx_->reseed_counter, sizeof(long long));
  return out;
}

void SyncDrbg::deserialize_hash_drbg_ctx(Buffer&& buf) {
  // public parameters
  ctx_->md = EVP_sha256();
  ctx_->hash_output_len = kHashDrbgHashOutputLen;
  ctx_->security_strength = kHashDrbgSecurityStrength;
  ctx_->seed_byte_len = kSeedByteLen;

  // synced internal states
  memcpy(ctx_->V, buf.data(), MAX_SEED_BYTE_LENGTH);
  memcpy(ctx_->C, (unsigned char*)buf.data() + MAX_SEED_BYTE_LENGTH,
         MAX_SEED_BYTE_LENGTH);
  memcpy(&ctx_->reseed_counter,
         (unsigned char*)buf.data() + 2 * MAX_SEED_BYTE_LENGTH,
         sizeof(long long));
}

// constructor
SyncDrbg::SyncDrbg(ByteContainerView nonce, ByteContainerView personal_string) {
  YACL_ENFORCE(nonce.size() <= 32);            // 2^35 bits = 2^32 bytes;
  YACL_ENFORCE(personal_string.size() <= 32);  // 2^35 bits = 2^32 bytes;

  // default seeded using yacl's entropy source
  auto es = EntropySourceFactory::Instance().Create("auto");

  // For intel chips:
  // The assessed entropy from the noise source is min(Hr, Hc, HI) = 0.6 bits
  // of entropy per bit of data. Therefore, to acquire n bits of entropy, the
  // output bitstring length (in bytes) would be (ceil(n/0.6) + 7 / 8)
  //
  // For amd chips:
  // The assessed entropy from the noise source is approx. min(Hr, Hc, HI) =
  // 0.3 bits per 128-bit rdseed output.
  //
  // Therefore it's sufficient for us to request (entropy_bits / 0.3) random
  // bits in both cases.
  //
  // For more detailed info, please see:
  // + yacl/crypto/rand/entropy_source/rdseed_factory.cc
  //
  // In this case, we assume kSeedByteLen = entropy_bits
  //
  uint32_t num_bytes = ((kSeedByteLen * 8 * 10 + 2) / 3 + 7) / 8;
  Buffer seed = es->GetEntropy(num_bytes);

  // instantiate drbg context
  const EVP_MD* md = EVP_sha256(); /* use sha256 */
  ctx_ = HashDrbgCtx(hash_drbg_ctx_new());
  YACL_ENFORCE(hash_drbg_instantiate(md, (unsigned char*)seed.data(),
                                     seed.size(), (unsigned char*)nonce.data(),
                                     nonce.size(),
                                     (unsigned char*)personal_string.data(),
                                     personal_string.size(), ctx_.get()) == 0);
}

// fill the output with generated randomness
int SyncDrbg::Fill(char* buf, size_t len,
                   ByteContainerView additional_data) const noexcept {
  if (additional_data.size() > 32) {  // 2^35 bits = 2^32 bytes;
    return 0;
  }

  if (sync_flag_) {
    SPDLOG_WARN(
        "SyncDrbg is in the syncing process ... quit `Fill` silently, no "
        "randomnesses are filled");
    return 0;
  }

  // drbg syncing
  const auto batch_num = (len + kBatchSize - 1) / kBatchSize;

  // for each batch, fill the randomness
  for (uint32_t step = 0; step < batch_num; step++) {
    const uint32_t limit = std::min(kBatchSize, len - step * kBatchSize);
    auto* offset = buf + step * kBatchSize;

    // The maximum length of pseudorandom bytes generated by this function
    // is 65536-byte. When more pseudorandom bytes are required, this
    // function must be invoked iteratively.
    int rc = gen_rnd_bytes_with_hash_drbg(
        ctx_.get(), limit, (unsigned char*)additional_data.data(),
        additional_data.size(), reinterpret_cast<unsigned char*>(offset));
    if (rc == REQUIRE_RESEED) {
      SPDLOG_WARN("Reseed Drbg Needed");
      Reseed();
    } else if (rc == 0) {
      /* succeed */
    } else {
      return 0;
    }
  }
  return 1;
}

// reseed
void SyncDrbg::Reseed(ByteContainerView additional_data) const {
  YACL_ENFORCE(additional_data.size() <= 32);  // 2^35 bits = 2^32 bytes;
  // default seeded using yacl's entropy source
  auto es = EntropySourceFactory::Instance().Create("auto");
  uint32_t num_bytes = ((kSeedByteLen * 8 * 10 + 2) / 3 + 7) / 8;
  Buffer seed = es->GetEntropy(num_bytes);

  YACL_ENFORCE(reseed_hash_drbg(ctx_.get(), (unsigned char*)seed.data(),
                                seed.size(),
                                (unsigned char*)additional_data.data(),
                                additional_data.size()) == 0);
}

// this op is blocked, and the return value signals the sync result, if
// returned true, sync process succeed, and fail otherwise.
void SyncDrbg::SendState(const std::shared_ptr<link::Context>& lctx,
                         size_t recv_rank) {
  YACL_ENFORCE(recv_rank != lctx->Rank());  // you should not sync with yourself
  std::lock_guard<std::mutex> lock{sync_mutex_};
  sync_flag_ = true;
  lctx->Send(recv_rank, serialize_hash_drbg_ctx(), "SyncDrbg send state");

  // additional ack message to make sure sync is blocked
  auto buf = lctx->Recv(recv_rank, "SycnDrbg:ACKs");
  YACL_ENFORCE(*(char*)buf.data() == 'Y');
  sync_flag_ = false;
  /* automatically unlocks when finished */
}

// this op is blocked, and the return value signals the sync result, if
// returned true, sync process succeed, and fail otherwise.
void SyncDrbg::RecvState(const std::shared_ptr<link::Context>& lctx,
                         size_t send_rank) {
  YACL_ENFORCE(send_rank != lctx->Rank());  // you should not sync with yourself
  std::lock_guard<std::mutex> lock{sync_mutex_};
  sync_flag_ = true;
  deserialize_hash_drbg_ctx(lctx->Recv(send_rank, "SyncDrbg recv state"));

  // additional ack message to make sure sync is blocked
  lctx->Send(send_rank, "Y", "SycnDrbg:ACKs");
  sync_flag_ = false;
  /* automatically unlocks when finished */
}

}  // namespace yacl::crypto
