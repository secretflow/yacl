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

#include "yacl/crypto/primitives/vole/f2k/sparse_vole.h"

#include <numeric>

#include "sparse_vole.h"

#include "yacl/base/aligned_vector.h"
#include "yacl/base/byte_container_view.h"
#include "yacl/crypto/primitives/ot/gywz_ote.h"
#include "yacl/crypto/primitives/ot/sgrr_ote.h"
#include "yacl/crypto/tools/random_permutation.h"
#include "yacl/math/f2k/f2k.h"
#include "yacl/math/gadget.h"
#include "yacl/utils/serialize.h"

namespace yacl::crypto {

namespace {
constexpr uint32_t kSuperBatch = 16;
}

// void SpVoleSend(const std::shared_ptr<link::Context>& ctx,
//                 const OtSendStore& /*rot*/ send_ot, uint32_t n, uint128_t w,
//                 absl::Span<uint128_t> output) {
//   SgrrOtExtSend(ctx, send_ot, n, output);
//   uint128_t send_msg = w;
//   for (uint32_t i = 0; i < n; ++i) {
//     send_msg ^= output[i];
//   }
//   ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(send_msg),
//                  "SpVole_msg");
// }

// void SpVoleRecv(const std::shared_ptr<link::Context>& ctx,
//                 const OtRecvStore& /*rot*/ recv_ot, uint32_t n, uint32_t
//                 index, uint128_t v, absl::Span<uint128_t> output) {
//   SgrrOtExtRecv(ctx, recv_ot, n, index, output);
//   auto recv_buff = ctx->Recv(ctx->NextRank(), "SpVole_msg");
//   auto recv_msg = DeserializeUint128(ByteContainerView(recv_buff));
//   for (uint32_t i = 0; i < n; ++i) {
//     recv_msg ^= output[i];
//   }
//   output[index] = recv_msg ^ v;
// }

void SpVoleSend(const std::shared_ptr<link::Context>& ctx,
                const OtSendStore& /*cot*/ send_ot, uint32_t n, uint128_t w,
                absl::Span<uint128_t> output) {
  GywzOtExtSend(ctx, send_ot, n, output);
  ParaCrHashInplace_128(output.subspan(0, n));
  uint128_t send_msg = w;
  for (uint32_t i = 0; i < n; ++i) {
    send_msg ^= output[i];
  }
  ctx->SendAsync(ctx->NextRank(), SerializeUint128(send_msg), "SpVole_msg");
}

void SpVoleRecv(const std::shared_ptr<link::Context>& ctx,
                const OtRecvStore& /*cot*/ recv_ot, uint32_t n, uint32_t index,
                uint128_t v, absl::Span<uint128_t> output) {
  GywzOtExtRecv(ctx, recv_ot, n, index, output);
  ParaCrHashInplace_128(output.subspan(0, n));
  output[index] = 0;
  auto recv_buff = ctx->Recv(ctx->NextRank(), "SpVole_msg");
  auto recv_msg = DeserializeUint128(ByteContainerView(recv_buff));
  for (uint32_t i = 0; i < n; ++i) {
    recv_msg ^= output[i];
  }
  output[index] = recv_msg ^ v;
}

// void MpVoleSend(const std::shared_ptr<link::Context>& ctx,
//                 const OtSendStore& /*rot*/ send_ot, const MpVoleParam& param,
//                 absl::Span<uint128_t> w, absl::Span<uint128_t> output) {
//   YACL_ENFORCE(param.assumption_ == LpnNoiseAsm::RegularNoise);
//   YACL_ENFORCE(output.size() >= param.mp_vole_size_);
//   YACL_ENFORCE(w.size() >= param.noise_num_);
//   YACL_ENFORCE(send_ot.Size() >= param.require_ot_num_);

//   const auto& batch_num = param.noise_num_;
//   const auto& batch_size = param.sp_vole_size_;
//   const auto& last_batch_size = param.last_sp_vole_size_;

//   for (uint32_t i = 0; i < batch_num; ++i) {
//     auto this_size = (i == batch_num - 1) ? last_batch_size : batch_size;

//     // TODO: @wenfan
//     // "Slice" would force to slice original OtStore from "begin" to "end",
//     // which might cause unexpected error.
//     // It would be better to use "NextSlice" here, but it's not a const
//     // function.
//     auto ot_slice = send_ot.Slice(
//         i * math::Log2Ceil(batch_size),
//         i * math::Log2Ceil(batch_size) + math::Log2Ceil(this_size));
//     SpVoleSend(ctx, ot_slice, this_size, w[i],
//                output.subspan(i * batch_size, this_size));
//   }
// }

// void MpVoleRecv(const std::shared_ptr<link::Context>& ctx,
//                 const OtRecvStore& /*rot*/ recv_ot, const MpVoleParam& param,
//                 absl::Span<uint128_t> v, absl::Span<uint128_t> output) {
//   YACL_ENFORCE(param.assumption_ == LpnNoiseAsm::RegularNoise);
//   YACL_ENFORCE(output.size() >= param.mp_vole_size_);
//   YACL_ENFORCE(v.size() >= param.noise_num_);
//   YACL_ENFORCE(recv_ot.Size() >= param.require_ot_num_);

//   const auto& batch_num = param.noise_num_;
//   const auto& batch_size = param.sp_vole_size_;
//   const auto& last_batch_size = param.last_sp_vole_size_;
//   const auto& indexes = param.indexes_;

//   for (uint32_t i = 0; i < batch_num; ++i) {
//     auto this_size = (i == batch_num - 1) ? last_batch_size : batch_size;

//     // TODO: @wenfan
//     // "Slice" would force to slice original OtStore from "begin" to "end",
//     // which might cause unexpected error.
//     // It would be better to use "NextSlice" here, but it's not a const
//     // function.
//     auto ot_slice = recv_ot.Slice(
//         i * math::Log2Ceil(batch_size),
//         i * math::Log2Ceil(batch_size) + math::Log2Ceil(this_size));
//     SpVoleRecv(ctx, ot_slice, this_size, indexes[i], v[i],
//                output.subspan(i * batch_size, this_size));
//   }
// }

void MpVoleSend(const std::shared_ptr<link::Context>& ctx,
                const OtSendStore& /*cot*/ send_ot, const MpVoleParam& param,
                absl::Span<uint128_t> w, absl::Span<uint128_t> output) {
  YACL_ENFORCE(param.assumption_ == LpnNoiseAsm::RegularNoise);
  YACL_ENFORCE(output.size() >= param.mp_vole_size_);
  YACL_ENFORCE(w.size() >= param.noise_num_);
  YACL_ENFORCE(send_ot.Size() >= param.require_ot_num_);

  const auto& batch_num = param.noise_num_;
  const auto& batch_size = param.sp_vole_size_;
  const auto& last_batch_size = param.last_sp_vole_size_;

  auto send_msg = AlignedVector<uint128_t>(w.data(), w.data() + batch_num);

  for (uint32_t i = 0; i < batch_num; ++i) {
    auto this_size = (i == batch_num - 1) ? last_batch_size : batch_size;
    auto this_span = output.subspan(i * batch_size, this_size);

    // TODO: @wenfan
    // "Slice" would force to slice original OtStore from "begin" to "end",
    // which might cause unexpected error.
    // It would be better to use "NextSlice" here, but it's not a const
    // function.
    auto ot_slice = send_ot.Slice(
        i * math::Log2Ceil(batch_size),
        i * math::Log2Ceil(batch_size) + math::Log2Ceil(this_size));

    GywzOtExtSend(ctx, ot_slice, this_size, this_span);
  }
  // Break the correlation
  ParaCrHashInplace_128(output.subspan(0, param.mp_vole_size_));
  for (uint32_t i = 0; i < batch_num; ++i) {
    auto this_size = (i == batch_num - 1) ? last_batch_size : batch_size;
    auto this_span = output.subspan(i * batch_size, this_size);
    for (const auto element : this_span) {
      send_msg[i] ^= element;
    }
  }

  ctx->SendAsync(
      ctx->NextRank(),
      ByteContainerView(send_msg.data(), send_msg.size() * sizeof(uint128_t)),
      "MpVole_msg");
}

void MpVoleRecv(const std::shared_ptr<link::Context>& ctx,
                const OtRecvStore& /*cot*/ recv_ot, const MpVoleParam& param,
                absl::Span<uint128_t> v, absl::Span<uint128_t> output) {
  YACL_ENFORCE(param.assumption_ == LpnNoiseAsm::RegularNoise);
  YACL_ENFORCE(output.size() >= param.mp_vole_size_);
  YACL_ENFORCE(v.size() >= param.noise_num_);
  YACL_ENFORCE(recv_ot.Size() >= param.require_ot_num_);

  const auto& batch_num = param.noise_num_;
  const auto& batch_size = param.sp_vole_size_;
  const auto& last_batch_size = param.last_sp_vole_size_;
  const auto& indexes = param.indexes_;

  for (uint32_t i = 0; i < batch_num; ++i) {
    auto this_size = (i == batch_num - 1) ? last_batch_size : batch_size;
    auto this_span = output.subspan(i * batch_size, this_size);

    // TODO: @wenfan
    // "Slice" would force to slice original OtStore from "begin" to "end",
    // which might cause unexpected error.
    // It would be better to use "NextSlice" here, but it's not a const
    // function.
    auto ot_slice = recv_ot.Slice(
        i * math::Log2Ceil(batch_size),
        i * math::Log2Ceil(batch_size) + math::Log2Ceil(this_size));
    GywzOtExtRecv(ctx, ot_slice, this_size, indexes[i], this_span);
  }

  ParaCrHashInplace_128(output.subspan(0, param.mp_vole_size_));

  auto recv_buff = ctx->Recv(ctx->NextRank(), "MpVole_msg");

  YACL_ENFORCE(static_cast<uint64_t>(recv_buff.size()) >=
               batch_num * sizeof(uint128_t));

  auto recv_msg =
      absl::MakeSpan(reinterpret_cast<uint128_t*>(recv_buff.data()), batch_num);

  for (uint32_t i = 0; i < batch_num; ++i) {
    auto this_size = (i == batch_num - 1) ? last_batch_size : batch_size;
    auto this_span = output.subspan(i * batch_size, this_size);
    this_span[indexes[i]] = 0;  // set punctured value as zero
    for (const auto element : this_span) {
      recv_msg[i] ^= element;
    }
    this_span[indexes[i]] = recv_msg[i] ^ v[i];
  }
}

void MpVoleSend_fixindex(const std::shared_ptr<link::Context>& ctx,
                         const OtSendStore& /*cot*/ send_ot,
                         const MpVoleParam& param, absl::Span<uint128_t> w,
                         absl::Span<uint128_t> output) {
  YACL_ENFORCE(param.assumption_ == LpnNoiseAsm::RegularNoise);
  YACL_ENFORCE(output.size() >= param.mp_vole_size_);
  YACL_ENFORCE(w.size() >= param.noise_num_);
  YACL_ENFORCE(send_ot.Size() >= param.require_ot_num_);

  const auto& batch_num = param.noise_num_;
  const auto& batch_size = param.sp_vole_size_;
  const auto& last_batch_size = param.last_sp_vole_size_;
  const auto batch_length = math::Log2Ceil(batch_size);
  const auto last_batch_length = math::Log2Ceil(last_batch_size);

  // send message buff for GYWZ OTe
  auto gywz_send_msgs = std::vector<uint128_t>(
      batch_length * (kSuperBatch - 1) + last_batch_length);

  const auto super_batch_num = math::DivCeil(batch_num, kSuperBatch);

  for (uint32_t s = 0; s < super_batch_num; ++s) {
    const uint32_t bound =
        std::min<uint32_t>(kSuperBatch, batch_num - s * kSuperBatch);
    for (uint32_t i = 0; i < bound; ++i) {
      auto this_size = batch_size;
      auto this_length = batch_length;
      if (s == (super_batch_num - 1) && i == (bound - 1)) {
        this_size = last_batch_size;
        this_length = last_batch_length;
      }

      auto this_span =
          output.subspan((s * kSuperBatch + i) * batch_size, this_size);

      // TODO: @wenfan
      // "Slice" would force to slice original OtStore from "begin" to "end",
      // which might cause unexpected error.
      // It would be better to use "NextSlice" here, but it's not a const
      auto ot_slice =
          send_ot.Slice((s * kSuperBatch + i) * batch_length,
                        (s * kSuperBatch + i) * batch_length + this_length);
      auto send_span =
          absl::MakeSpan(gywz_send_msgs.data() + i * batch_length, this_length);
      // GywzOtExt is single-point COT
      GywzOtExtSend_fixindex(ot_slice, this_size, this_span, send_span);
    }

    auto msg_length = kSuperBatch * batch_length;
    if (s == (super_batch_num - 1)) {
      msg_length = (bound - 1) * batch_length + last_batch_length;
    }
    ctx->SendAsync(ctx->NextRank(),
                   ByteContainerView(gywz_send_msgs.data(),
                                     sizeof(uint128_t) * msg_length),
                   "GYWZ_OTE: messages");
  }

  // Break the correlation
  ParaCrHashInplace_128(output.subspan(0, param.mp_vole_size_));

  auto send_msgs = AlignedVector<uint128_t>(w.data(), w.data() + batch_num);

  for (uint32_t i = 0; i < batch_num; ++i) {
    auto this_size = (i == batch_num - 1) ? last_batch_size : batch_size;
    auto this_span = output.subspan(i * batch_size, this_size);
    for (const auto element : this_span) {
      send_msgs[i] ^= element;
    }
  }

  ctx->SendAsync(
      ctx->NextRank(),
      ByteContainerView(send_msgs.data(), send_msgs.size() * sizeof(uint128_t)),
      "MpVole_msg");
}

void MpVoleRecv_fixindex(const std::shared_ptr<link::Context>& ctx,
                         const OtRecvStore& /*cot*/ recv_ot,
                         const MpVoleParam& param, absl::Span<uint128_t> v,
                         absl::Span<uint128_t> output) {
  YACL_ENFORCE(param.assumption_ == LpnNoiseAsm::RegularNoise);
  YACL_ENFORCE(output.size() >= param.mp_vole_size_);
  YACL_ENFORCE(v.size() >= param.noise_num_);
  YACL_ENFORCE(recv_ot.Size() >= param.require_ot_num_);

  const auto& batch_num = param.noise_num_;
  const auto& batch_size = param.sp_vole_size_;
  const auto& last_batch_size = param.last_sp_vole_size_;
  const auto batch_length = math::Log2Ceil(batch_size);
  const auto last_batch_length = math::Log2Ceil(last_batch_size);

  const auto& indexes = param.indexes_;

  const auto super_batch_num = math::DivCeil(batch_num, kSuperBatch);

  for (uint32_t s = 0; s < super_batch_num; ++s) {
    const uint32_t bound =
        std::min<uint32_t>(kSuperBatch, batch_num - s * kSuperBatch);
    auto msg_length = kSuperBatch * batch_length;
    if (s == (super_batch_num - 1)) {
      msg_length = (bound - 1) * batch_length + last_batch_length;
    }

    auto gywz_recv_buf = ctx->Recv(ctx->NextRank(), "GYWZ_OTE: messages");
    YACL_ENFORCE(gywz_recv_buf.size() ==
                 static_cast<int64_t>(msg_length * sizeof(uint128_t)));
    auto gywz_recv_msgs = absl::MakeSpan(
        reinterpret_cast<uint128_t*>(gywz_recv_buf.data()), msg_length);

    for (uint32_t i = 0; i < bound; ++i) {
      auto this_size = batch_size;
      auto this_length = batch_length;
      if (s == (super_batch_num - 1) && i == (bound - 1)) {
        this_size = last_batch_size;
        this_length = last_batch_length;
      }

      auto this_span =
          output.subspan((s * kSuperBatch + i) * batch_size, this_size);
      // TODO: @wenfan
      // "Slice" would force to slice original OtStore from "begin" to "end",
      // which might cause unexpected error.
      // It would be better to use "NextSlice" here, but it's not a const
      auto ot_slice =
          recv_ot.Slice((s * kSuperBatch + i) * batch_length,
                        (s * kSuperBatch + i) * batch_length + this_length);
      auto recv_span =
          absl::MakeSpan(gywz_recv_msgs.data() + i * batch_length, this_length);
      // GywzOtExt is single-point COT
      GywzOtExtRecv_fixindex(ot_slice, this_size, this_span, recv_span);
    }
  }

  // Break the correlation
  ParaCrHashInplace_128(output.subspan(0, param.mp_vole_size_));

  auto recv_buff = ctx->Recv(ctx->NextRank(), "MpVole_msg");
  YACL_ENFORCE(static_cast<uint64_t>(recv_buff.size()) >=
               batch_num * sizeof(uint128_t));

  auto recv_msgs =
      absl::MakeSpan(reinterpret_cast<uint128_t*>(recv_buff.data()), batch_num);

  for (uint32_t i = 0; i < batch_num; ++i) {
    auto this_size = (i == batch_num - 1) ? last_batch_size : batch_size;
    auto this_span = output.subspan(i * batch_size, this_size);
    this_span[indexes[i]] = 0;  // set punctured value as zero
    for (const auto element : this_span) {
      recv_msgs[i] ^= element;
    }
    this_span[indexes[i]] = recv_msgs[i] ^ v[i];
  }
}

void MpVoleSend_fixindex(const std::shared_ptr<link::Context>& ctx,
                         const OtSendStore& /*cot*/ send_ot,
                         const MpVoleParam& param, absl::Span<uint64_t> w,
                         absl::Span<uint64_t> output) {
  YACL_ENFORCE(param.assumption_ == LpnNoiseAsm::RegularNoise);
  YACL_ENFORCE(output.size() >= param.mp_vole_size_);
  YACL_ENFORCE(w.size() >= param.noise_num_);
  YACL_ENFORCE(send_ot.Size() >= param.require_ot_num_);

  const auto& batch_num = param.noise_num_;
  const auto& batch_size = param.sp_vole_size_;
  const auto& last_batch_size = param.last_sp_vole_size_;
  const auto batch_length = math::Log2Ceil(batch_size);
  const auto last_batch_length = math::Log2Ceil(last_batch_size);

  // send message buff for GYWZ OTe
  auto gywz_send_msgs = std::vector<uint128_t>(
      batch_length * (kSuperBatch - 1) + last_batch_length);

  std::vector<uint128_t> mpvole_buff(param.mp_vole_size_);
  auto mpvole_span = absl::MakeSpan(mpvole_buff);
  const auto super_batch_num = math::DivCeil(batch_num, kSuperBatch);

  for (uint32_t s = 0; s < super_batch_num; ++s) {
    const uint32_t bound =
        std::min<uint32_t>(kSuperBatch, batch_num - s * kSuperBatch);
    for (uint32_t i = 0; i < bound; ++i) {
      auto this_size = batch_size;
      auto this_length = batch_length;
      if (s == (super_batch_num - 1) && i == (bound - 1)) {
        this_size = last_batch_size;
        this_length = last_batch_length;
      }

      auto this_span =
          mpvole_span.subspan((s * kSuperBatch + i) * batch_size, this_size);

      // TODO: @wenfan
      // "Slice" would force to slice original OtStore from "begin" to "end",
      // which might cause unexpected error.
      // It would be better to use "NextSlice" here, but it's not a const
      auto ot_slice =
          send_ot.Slice((s * kSuperBatch + i) * batch_length,
                        (s * kSuperBatch + i) * batch_length + this_length);
      auto send_span =
          absl::MakeSpan(gywz_send_msgs.data() + i * batch_length, this_length);
      GywzOtExtSend_fixindex(ot_slice, this_size, this_span, send_span);
    }

    auto msg_length = kSuperBatch * batch_length;
    if (s == (super_batch_num - 1)) {
      msg_length = (bound - 1) * batch_length + last_batch_length;
    }
    ctx->SendAsync(ctx->NextRank(),
                   ByteContainerView(gywz_send_msgs.data(),
                                     sizeof(uint128_t) * msg_length),
                   "GYWZ_OTE: messages");
  }

  // Break the correlation
  ParaCrHashInplace_128(mpvole_span.subspan(0, param.mp_vole_size_));

  auto send_msgs = AlignedVector<uint64_t>(w.data(), w.data() + batch_num);

  for (uint32_t i = 0; i < batch_num; ++i) {
    auto this_size = (i == batch_num - 1) ? last_batch_size : batch_size;
    auto this_span = output.subspan(i * batch_size, this_size);
    for (uint32_t j = 0; j < this_size; ++j) {
      this_span[j] = mpvole_span[batch_size * i + j];
      send_msgs[i] ^= this_span[j];
    }
  }

  ctx->SendAsync(
      ctx->NextRank(),
      ByteContainerView(send_msgs.data(), send_msgs.size() * sizeof(uint64_t)),
      "MpVole_msg");
}

void MpVoleRecv_fixindex(const std::shared_ptr<link::Context>& ctx,
                         const OtRecvStore& /*cot*/ recv_ot,
                         const MpVoleParam& param, absl::Span<uint64_t> v,
                         absl::Span<uint64_t> output) {
  YACL_ENFORCE(param.assumption_ == LpnNoiseAsm::RegularNoise);
  YACL_ENFORCE(output.size() >= param.mp_vole_size_);
  YACL_ENFORCE(v.size() >= param.noise_num_);
  YACL_ENFORCE(recv_ot.Size() >= param.require_ot_num_);

  const auto& batch_num = param.noise_num_;
  const auto& batch_size = param.sp_vole_size_;
  const auto& last_batch_size = param.last_sp_vole_size_;
  const auto batch_length = math::Log2Ceil(batch_size);
  const auto last_batch_length = math::Log2Ceil(last_batch_size);

  const auto& indexes = param.indexes_;

  std::vector<uint128_t> mpvole_buff(param.mp_vole_size_);
  auto mpvole_span = absl::MakeSpan(mpvole_buff);
  const auto super_batch_num = math::DivCeil(batch_num, kSuperBatch);

  for (uint32_t s = 0; s < super_batch_num; ++s) {
    const uint32_t bound =
        std::min<uint32_t>(kSuperBatch, batch_num - s * kSuperBatch);
    auto msg_length = kSuperBatch * batch_length;
    if (s == (super_batch_num - 1)) {
      msg_length = (bound - 1) * batch_length + last_batch_length;
    }

    auto gywz_recv_buf = ctx->Recv(ctx->NextRank(), "GYWZ_OTE: messages");
    YACL_ENFORCE(gywz_recv_buf.size() ==
                 static_cast<int64_t>(msg_length * sizeof(uint128_t)));
    auto gywz_recv_msgs = absl::MakeSpan(
        reinterpret_cast<uint128_t*>(gywz_recv_buf.data()), msg_length);

    for (uint32_t i = 0; i < bound; ++i) {
      auto this_size = batch_size;
      auto this_length = batch_length;
      if (s == (super_batch_num - 1) && i == (bound - 1)) {
        this_size = last_batch_size;
        this_length = last_batch_length;
      }

      auto this_span =
          mpvole_span.subspan((s * kSuperBatch + i) * batch_size, this_size);
      // TODO: @wenfan
      // "Slice" would force to slice original OtStore from "begin" to "end",
      // which might cause unexpected error.
      // It would be better to use "NextSlice" here, but it's not a const
      auto ot_slice =
          recv_ot.Slice((s * kSuperBatch + i) * batch_length,
                        (s * kSuperBatch + i) * batch_length + this_length);
      auto recv_span =
          absl::MakeSpan(gywz_recv_msgs.data() + i * batch_length, this_length);
      GywzOtExtRecv_fixindex(ot_slice, this_size, this_span, recv_span);
    }
  }

  // Break the correlation
  ParaCrHashInplace_128(mpvole_span.subspan(0, param.mp_vole_size_));

  auto recv_buff = ctx->Recv(ctx->NextRank(), "MpVole_msg");
  YACL_ENFORCE(static_cast<uint64_t>(recv_buff.size()) >=
               batch_num * sizeof(uint64_t));

  auto recv_msgs =
      absl::MakeSpan(reinterpret_cast<uint64_t*>(recv_buff.data()), batch_num);

  for (uint32_t i = 0; i < batch_num; ++i) {
    auto this_size = (i == batch_num - 1) ? last_batch_size : batch_size;
    auto this_span = output.subspan(i * batch_size, this_size);
    // set punctured value as zero
    mpvole_span[i * batch_size + indexes[i]] = 0;
    for (uint32_t j = 0; j < this_size; ++j) {
      this_span[j] = mpvole_span[i * batch_size + j];
      recv_msgs[i] ^= this_span[j];
    }
    this_span[indexes[i]] = recv_msgs[i] ^ v[i];
  }
}

}  // namespace yacl::crypto
