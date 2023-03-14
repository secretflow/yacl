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

#include "yacl/crypto/primitives/ot/kkrt_ote.h"

#include <algorithm>
#include <array>
#include <vector>

#include "c/blake3.h"

#include "yacl/base/block.h"
#include "yacl/base/byte_container_view.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/base/aes/aes_opt.h"
#include "yacl/crypto/base/hash/hash_utils.h"
#include "yacl/crypto/base/symmetric_crypto.h"
#include "yacl/crypto/tools/prg.h"
#include "yacl/crypto/tools/random_oracle.h"
#include "yacl/crypto/utils/rand.h"
#include "yacl/utils/matrix_utils.h"
#include "yacl/utils/serialize.h"
namespace yacl::crypto {

namespace {

constexpr int kKappa = 128;                      // Security Parameter
constexpr int kIknpWidth = kKkrtWidth * kKappa;  // IKNP OT Extension Width
// TODO(shuyan.ycf): switch to 1024 when we have efficient 1024x128 transpose.
constexpr int kBatchSize = 128;  // How many blocks do we have.
constexpr int kNumBlockPerBatch = kBatchSize / kKappa;
constexpr int kPrgBatchSize = kBatchSize * kNumBlockPerBatch;
static_assert(kBatchSize % kKappa == 0);
constexpr int kBatchSize1024 = 1024;
constexpr int kNumBlockPerBatch1024 = kBatchSize1024 / kKappa;
constexpr int kPrgBatchSize1024 = kBatchSize * kNumBlockPerBatch1024;
static_assert(kBatchSize1024 % kKappa == 0);

// Pseudorandom coding initialization
inline void PrcInit(const std::shared_ptr<link::Context>& ctx,
                    AES_KEY* aes_key) {
  uint128_t my_seed = SecureRandSeed();
  ctx->SendAsync(ctx->NextRank(), SerializeUint128(my_seed), "SEED");
  auto peer_seed = DeserializeUint128(ctx->Recv(ctx->NextRank(), "SEED"));
  auto keys_block = PrgAesCtr<uint128_t>(my_seed ^ peer_seed, kKkrtWidth);
  AES_opt_key_schedule<kKkrtWidth>(keys_block.data(), aes_key);
}

// Apply Pseudorandom coding on the input
inline void Prc(AES_KEY* aes_key, uint128_t input, KkrtRow* prc) {
  std::array<uint128_t, kKkrtWidth> aes_blocks;
  std::fill(aes_blocks.begin(), aes_blocks.end(), input);
  ParaEnc<kKkrtWidth, 1>(aes_blocks.data(), aes_key);
  for (size_t i = 0; i < kKkrtWidth; i++) {
    // aes(x) xor x, Correlation Roustness Hash
    (*prc)[i] = aes_blocks[i] ^ input;
  }
}

}  // namespace

class KkrtGroupPRF : public IGroupPRF {
 public:
  explicit KkrtGroupPRF(const std::shared_ptr<link::Context>& ctx, size_t n,
                        const KkrtRow& s)
      : size_(n), q_(n, {0}), s_(s) {
    PrcInit(ctx, aes_key_);
  }

  size_t Size() const override { return size_; }

  // According to KKRT paper, the final PRF output should be: H(q ^ (c(r) & s))
  uint128_t Eval(size_t group_idx, uint128_t input) override {
    YACL_ENFORCE_LT(group_idx, size_);
    KkrtRow prc_buf;
    Prc(aes_key_, input, &prc_buf);
    const auto& q = q_[group_idx];

    for (size_t w = 0; w < kKkrtWidth; ++w) {
      prc_buf[w] &= s_[w];
      prc_buf[w] ^= q[w];
    }

    return RO_Blake3_128(ByteContainerView(prc_buf.data(), sizeof(prc_buf)));
  }

  // According to KKRT paper, the final PRF output should be: H(q ^ (c(r) & s))
  void Eval(size_t group_idx, uint128_t input, uint8_t* outbuf,
            size_t bufsize) override {
    YACL_ENFORCE_LT(group_idx, size_);
    KkrtRow prc;
    Prc(aes_key_, input, &prc);
    const auto& q = q_[group_idx];

    for (size_t w = 0; w < kKkrtWidth; ++w) {
      prc[w] &= s_[w];
      prc[w] ^= q[w];
    }

    const auto& RO = RandomOracle::GetBlake3();
    auto tmp = RO(ByteContainerView(prc.data(), sizeof(prc)), bufsize);
    std::memcpy(outbuf, tmp.data(), bufsize);
  }

  template <size_t N>
  void SetQ(const std::array<KkrtRow, N>& q, size_t offset, size_t num_valid) {
    YACL_ENFORCE(num_valid <= q.size() && offset + num_valid <= this->Size());
    for (size_t i = 0; i < num_valid; ++i) {
      q_[offset + i] = q[i];
    }
  }

  template <size_t N>
  void CalcQ(const std::array<KkrtRow, N>& u, size_t offset, size_t num_valid) {
    YACL_ENFORCE(num_valid <= u.size() && offset + num_valid <= this->Size());
    std::array<KkrtRow, N> t;
    for (size_t i = 0; i < num_valid; ++i) {
      for (size_t w = 0; w < kKkrtWidth; ++w) {
        t[i][w] = u[i][w] & s_[w];
        q_[offset + i][w] ^= t[i][w];
      }
    }
  }

  void CalcQ(const std::vector<KkrtRow>& u, size_t offset, size_t num_valid) {
    YACL_ENFORCE(num_valid <= u.size());
    YACL_ENFORCE(offset + num_valid <= this->Size());
    std::vector<KkrtRow> t;
    t.resize(num_valid);
    for (size_t i = 0; i < num_valid; ++i) {
      for (size_t w = 0; w < kKkrtWidth; ++w) {
        t[i][w] = u[i][w] & s_[w];
        q_[offset + i][w] ^= t[i][w];
      }
    }
  }

 private:
  const size_t size_;       // Group size.
  std::vector<KkrtRow> q_;  // Q, received from receiver.
  KkrtRow s_;               // Sender base ot choice bits: `s`

  AES_KEY aes_key_[kKkrtWidth];
};

std::unique_ptr<IGroupPRF> KkrtOtExtSend(
    const std::shared_ptr<link::Context>& ctx,
    const std::shared_ptr<OtRecvStore>& base_ot, size_t num_ot) {
  YACL_ENFORCE_EQ(kIknpWidth, (int)base_ot->Size());
  YACL_ENFORCE(num_ot > 0);

  // Build S for sender.
  KkrtRow S{0};
  for (size_t w = 0; w < kKkrtWidth; ++w) {
    for (size_t k = 0; k < kKappa; ++k) {
      S[w] |= uint128_t(base_ot->GetChoice(w * kKappa + k)) << k;
    }
  }
  // Build PRG from seed Ks.
  std::vector<Prg<uint128_t, kPrgBatchSize>> prgs;
  for (size_t k = 0; k < kIknpWidth; ++k) {
    prgs.emplace_back(base_ot->GetBlock(k));
  }

  // Build PRF.
  auto prf = std::make_unique<KkrtGroupPRF>(ctx, num_ot, S);

  const size_t num_batch = (num_ot + kBatchSize - 1) / kBatchSize;
  for (size_t batch_idx = 0; batch_idx < num_batch; ++batch_idx) {
    const size_t num_this_batch =
        std::min<size_t>(num_ot - batch_idx * kBatchSize, kBatchSize);
    std::array<KkrtRow, kBatchSize> Q;
    std::array<KkrtRow, kBatchSize> U;
    for (size_t w = 0; w < kKkrtWidth; ++w) {
      std::array<uint128_t, kBatchSize> q;
      for (size_t k = 0; k < kKappa; ++k) {
        const size_t col_idx = w * kKappa + k;
        for (size_t b = 0; b < kNumBlockPerBatch; ++b) {
          q[k * kNumBlockPerBatch + b] = prgs[col_idx]();
        }
      }
      SseTranspose128(&q);
      for (size_t i = 0; i < num_this_batch; ++i) {
        Q[i][w] = q[i];  // Q = G(ks)
      }
    }

    // Receive U.
    auto buf = ctx->Recv(ctx->NextRank(), fmt::format("KKRT:{}", batch_idx));
    YACL_ENFORCE_EQ(buf.size(), static_cast<int64_t>(sizeof(U)));
    std::memcpy(U.data(), buf.data(), sizeof(U));

    // Build Q = (U & S) ^ G(ks)
    for (size_t i = 0; i < num_this_batch; ++i) {
      for (size_t w = 0; w < kKkrtWidth; ++w) {
        U[i][w] &= S[w];
        Q[i][w] ^= U[i][w];
      }
    }

    // Set to PRF.
    prf->SetQ(Q, batch_idx * kBatchSize, num_this_batch);
  }

  return prf;
}

void KkrtOtExtRecv(const std::shared_ptr<link::Context>& ctx,
                   const std::shared_ptr<OtSendStore>& base_ot,
                   absl::Span<const uint128_t> inputs,
                   absl::Span<uint128_t> recv_blocks) {
  YACL_ENFORCE(base_ot->Size() == kIknpWidth);
  YACL_ENFORCE(inputs.size() == recv_blocks.size() && !inputs.empty());

  const size_t num_ot = inputs.size();
  const size_t num_batch = (num_ot + kBatchSize - 1) / kBatchSize;

  std::vector<Prg<uint128_t, kPrgBatchSize>> prgs0;
  std::vector<Prg<uint128_t, kPrgBatchSize>> prgs1;
  for (size_t k = 0; k < kIknpWidth; ++k) {
    // Build PRG from seed K0.
    prgs0.emplace_back(base_ot->GetBlock(k, 0));
    // Build PRG from seed K1.
    prgs1.emplace_back(base_ot->GetBlock(k, 1));
  }
  AES_KEY aes_key[kKkrtWidth];
  PrcInit(ctx, aes_key);

  // Let us do it streaming way.
  for (size_t batch_idx = 0; batch_idx < num_batch; ++batch_idx) {
    const size_t num_this_batch =
        std::min<size_t>(num_ot - batch_idx * kBatchSize, kBatchSize);
    // KKRT can be viewed as a wider IKNP OT EXTENSION.
    std::array<KkrtRow, kBatchSize> T;
    std::array<KkrtRow, kBatchSize> U;
    for (size_t w = 0; w < kKkrtWidth; ++w) {
      std::array<uint128_t, kBatchSize> t;
      std::array<uint128_t, kBatchSize> u;
      for (size_t k = 0; k < kKappa; ++k) {
        const size_t col_idx = w * kKappa + k;
        for (size_t b = 0; b < kNumBlockPerBatch; ++b) {
          t[k * kNumBlockPerBatch + b] = prgs0[col_idx]();
          u[k * kNumBlockPerBatch + b] = prgs1[col_idx]();
        }
      }

      SseTranspose128(&t);
      SseTranspose128(&u);
      for (size_t i = 0; i < num_this_batch; ++i) {
        T[i][w] = t[i];  // T = G(k0)
        U[i][w] = u[i];  // U = G(k1)
      }
    }
    // Construct U.
    // U = G(k1) ^ G(k0) ^ PRC(r)
    for (size_t i = 0; i < num_this_batch; ++i) {
      KkrtRow prc;
      Prc(aes_key, inputs[batch_idx * kBatchSize + i], &prc);
      for (size_t w = 0; w < kKkrtWidth; ++w) {
        U[i][w] ^= T[i][w];
        U[i][w] ^= prc[w];
      }
    }
    ctx->SendAsync(ctx->NextRank(),
                   ByteContainerView{
                       reinterpret_cast<const std::byte*>(U.data()), sizeof(U)},
                   fmt::format("KKRT:{}", batch_idx));
    for (size_t i = 0; i < num_this_batch; ++i) {
      recv_blocks[batch_idx * kBatchSize + i] =
          RO_Blake3_128(ByteContainerView(T[i].data(), sizeof(T[i])));
    }
  }
}

void KkrtOtExtSender::Init(const std::shared_ptr<link::Context>& ctx,
                           const std::shared_ptr<OtRecvStore>& base_ot,
                           uint64_t num_ot) {
  YACL_ENFORCE(kIknpWidth == base_ot->Size());
  YACL_ENFORCE(num_ot > 0);

  correction_idx_ = 0;

  // Build S for sender.
  KkrtRow S{0};
  for (size_t w = 0; w < kKkrtWidth; ++w) {
    for (size_t k = 0; k < kKappa; ++k) {
      S[w] |= uint128_t(base_ot->GetChoice(w * kKappa + k) ? 1 : 0) << k;
    }
  }
  // Build PRG from seed Ks.
  std::vector<Prg<uint128_t, kPrgBatchSize1024>> prgs;

  for (size_t k = 0; k < kIknpWidth; ++k) {
    prgs.emplace_back(base_ot->GetBlock(k));
  }

  // Build PRF.
  auto kkrt_oprf = std::make_shared<KkrtGroupPRF>(ctx, num_ot, S);
  oprf_ = kkrt_oprf;

  const size_t num_batch = (num_ot + kBatchSize1024 - 1) / kBatchSize1024;
  for (size_t batch_idx = 0; batch_idx < num_batch; ++batch_idx) {
    const size_t num_this_batch =
        std::min<size_t>(num_ot - batch_idx * kBatchSize1024, kBatchSize1024);
    std::array<KkrtRow, kBatchSize1024> Q;
    for (size_t w = 0; w < kKkrtWidth; ++w) {
      std::array<std::array<block, kNumBlockPerBatch1024>, kKappa> q;
      for (size_t k = 0; k < kKappa; ++k) {
        const size_t col_idx = w * kKappa + k;

        for (size_t j = 0; j < kNumBlockPerBatch1024; ++j) {
          q[k][j] = prgs[col_idx]();
        }
      }
      SseTranspose128x1024(q);

      for (size_t i = 0; i < kNumBlockPerBatch1024; ++i) {
        size_t q_idx = i * kKappa;
        size_t q_batch_num = std::min((size_t)kKappa, num_this_batch - q_idx);

        for (size_t j = 0; j < q_batch_num; ++j) {
          Q[q_idx + j][w] = (uint128_t)(q[j][i].mData);
        }
        if (q_batch_num < kKappa) {
          break;
        }
      }
    }

    // Set to PRF.
    kkrt_oprf->SetQ(Q, batch_idx * kBatchSize1024, num_this_batch);
  }
}

void KkrtOtExtSender::RecvCorrection(const std::shared_ptr<link::Context>& ctx,
                                     uint64_t recv_count) {
  std::vector<KkrtRow> U;

  U.resize(recv_count);
  // Receive U.
  auto buf = ctx->Recv(ctx->NextRank(), fmt::format("KKRT:{}", recv_count));

  YACL_ENFORCE_EQ(buf.size(), static_cast<int64_t>(U.size() * sizeof(KkrtRow)));

  std::memcpy(U.data(), buf.data(), U.size() * sizeof(KkrtRow));

  std::shared_ptr<KkrtGroupPRF> kkrtOprf =
      std::dynamic_pointer_cast<KkrtGroupPRF>(oprf_);
  kkrtOprf->CalcQ(U, correction_idx_, recv_count);
  correction_idx_ += recv_count;
}

void KkrtOtExtSender::SetCorrection(const yacl::Buffer& recvceived_correction,
                                    uint64_t recv_count) {
  std::vector<KkrtRow> U;

  U.resize(recv_count);
  // set U.
  YACL_ENFORCE_EQ(recvceived_correction.size(),
                  static_cast<int64_t>(U.size() * sizeof(KkrtRow)));
  std::memcpy(U.data(), recvceived_correction.data(),
              U.size() * sizeof(KkrtRow));

  std::shared_ptr<KkrtGroupPRF> kkrtOprf =
      std::dynamic_pointer_cast<KkrtGroupPRF>(oprf_);
  kkrtOprf->CalcQ(U, correction_idx_, recv_count);
  correction_idx_ += recv_count;
}

void KkrtOtExtSender::Encode(uint64_t ot_idx, const uint128_t input, void* dest,
                             uint64_t dest_size) {
  oprf_->Eval(ot_idx, input, (uint8_t*)dest, dest_size);
}

void KkrtOtExtReceiver::Init(const std::shared_ptr<link::Context>& ctx,
                             const std::shared_ptr<OtSendStore>& base_ot,
                             uint64_t num_ot) {
  const size_t num_batch = (num_ot + kBatchSize1024 - 1) / kBatchSize1024;

  PrcInit(ctx, aes_key_);

  std::vector<Prg<uint128_t>> prgs0;
  std::vector<Prg<uint128_t>> prgs1;

  for (size_t k = 0; k < kIknpWidth; ++k) {
    prgs0.emplace_back(base_ot->GetBlock(k, 0));  // Build PRG from seed K0.
    prgs1.emplace_back(base_ot->GetBlock(k, 1));  // Build PRG from seed K1.
  }

  T_.resize(num_ot);
  U_.resize(num_ot);
  correction_idx_ = 0;

  // Let us do it streaming way.
  for (size_t batch_idx = 0; batch_idx < num_batch; ++batch_idx) {
    const size_t num_this_batch =
        std::min<size_t>(num_ot - batch_idx * kBatchSize1024, kBatchSize1024);
    // KKRT can be viewed as a wider IKNP OT EXTENSION.
    for (size_t w = 0; w < kKkrtWidth; ++w) {
      std::array<std::array<block, kNumBlockPerBatch1024>, kKappa> t;
      std::array<std::array<block, kNumBlockPerBatch1024>, kKappa> u;
      for (size_t k = 0; k < kKappa; ++k) {
        const size_t col_idx = w * kKappa + k;
        for (size_t j = 0; j < kNumBlockPerBatch1024; ++j) {
          t[k][j] = prgs0[col_idx]();
          u[k][j] = prgs1[col_idx]();
        }
      }
      SseTranspose128x1024(t);
      SseTranspose128x1024(u);

      size_t batch_start = batch_idx * kBatchSize1024;
      for (size_t i = 0; i < kNumBlockPerBatch1024; ++i) {
        size_t tu_idx = i * kKappa;
        size_t tu_batch_num = std::min((size_t)kKappa, num_this_batch - tu_idx);

        for (size_t j = 0; j < tu_batch_num; ++j) {
          // T = G(k0)
          T_[batch_start + tu_idx + j][w] = (uint128_t)t[j][i].mData;
          // U = G(k1)
          U_[batch_start + tu_idx + j][w] = (uint128_t)u[j][i].mData;
        }
        if (tu_batch_num < kKappa) {
          break;
        }
      }
    }
  }
}

void KkrtOtExtReceiver::Encode(uint64_t ot_idx,
                               absl::Span<const uint128_t> inputs,
                               absl::Span<uint8_t> dest_encode) {
  YACL_ENFORCE(dest_encode.size() <= sizeof(uint128_t));

  KkrtRow prc;
  Prc(aes_key_, inputs[ot_idx], &prc);

  for (size_t w = 0; w < kKkrtWidth; ++w) {
    U_[ot_idx][w] ^= T_[ot_idx][w];
    U_[ot_idx][w] ^= prc[w];
  }

  const auto& RO = RandomOracle::GetBlake3();
  const size_t bufsize = std::min(dest_encode.size(), sizeof(uint128_t));
  auto tmp =
      RO(ByteContainerView(T_[ot_idx].data(), sizeof(T_[ot_idx])), bufsize);
  std::memcpy(dest_encode.data(), tmp.data(), bufsize);
}

void KkrtOtExtReceiver::Encode(uint64_t ot_idx, const uint128_t input,
                               absl::Span<uint8_t> dest_encode) {
  YACL_ENFORCE(dest_encode.size() <= sizeof(uint128_t));

  KkrtRow prc;
  Prc(aes_key_, input, &prc);

  for (size_t w = 0; w < kKkrtWidth; ++w) {
    U_[ot_idx][w] ^= T_[ot_idx][w];
    U_[ot_idx][w] ^= prc[w];
  }

  const auto& RO = RandomOracle::GetBlake3();
  const size_t bufsize = std::min(dest_encode.size(), sizeof(uint128_t));
  auto tmp =
      RO(ByteContainerView(T_[ot_idx].data(), sizeof(T_[ot_idx])), bufsize);
  std::memcpy(dest_encode.data(), tmp.data(), bufsize);
}

void KkrtOtExtReceiver::ZeroEncode(uint64_t ot_idx) {
  for (size_t w = 0; w < kKkrtWidth; ++w) {
    U_[ot_idx][w] ^= T_[ot_idx][w];
  }
}

void KkrtOtExtReceiver::SendCorrection(
    const std::shared_ptr<link::Context>& ctx, uint64_t send_count) {
  ctx->SendAsync(ctx->NextRank(),
                 ByteContainerView{reinterpret_cast<const char*>(U_.data()) +
                                       (correction_idx_ * sizeof(KkrtRow)),
                                   send_count * sizeof(KkrtRow)},
                 fmt::format("KKRT:{}", send_count));
  correction_idx_ += send_count;
}

yacl::Buffer KkrtOtExtReceiver::ShiftCorrection(uint64_t send_count) {
  yacl::Buffer buf(reinterpret_cast<const char*>(U_.data()) +
                       (correction_idx_ * sizeof(KkrtRow)),
                   send_count * sizeof(KkrtRow));
  correction_idx_ += send_count;
  return buf;
}

}  // namespace yacl::crypto
