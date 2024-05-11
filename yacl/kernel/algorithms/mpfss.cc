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

#include "mpfss.h"

#include <algorithm>
#include <numeric>

#include "yacl/base/aligned_vector.h"
#include "yacl/base/byte_container_view.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/tools/crhash.h"
#include "yacl/kernel/algorithms/gywz_ote.h"
#include "yacl/kernel/algorithms/sgrr_ote.h"
#include "yacl/math/f2k/f2k.h"
#include "yacl/math/gadget.h"

namespace yacl::crypto {

namespace {
constexpr uint32_t kSuperBatch = 16;
}

void MpfssSend(const std::shared_ptr<link::Context>& ctx,
               const OtSendStore& /*cot*/ send_ot, const MpFssParam& param,
               absl::Span<const uint128_t> w, absl::Span<uint128_t> output,
               const MpfssOp<uint128_t>& op) {
  YACL_ENFORCE(param.assumption_ == LpnNoiseAsm::RegularNoise);
  YACL_ENFORCE(output.size() >= param.mp_vole_size_);
  YACL_ENFORCE(w.size() >= param.noise_num_);
  YACL_ENFORCE(send_ot.Size() >= param.require_ot_num_);

  const auto& batch_num = param.noise_num_;
  const auto& batch_size = param.sp_vole_size_;
  const auto& last_batch_size = param.last_sp_vole_size_;

  UninitAlignedVector<uint128_t> send_msgs(batch_num, 0);
  std::transform(send_msgs.cbegin(), send_msgs.cend(), w.cbegin(),
                 send_msgs.begin(), op.sub);

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
    // Break the correlation
    ParaCrHashInplace_128(this_span);
    send_msgs[i] =
        std::reduce(this_span.begin(), this_span.end(), send_msgs[i], op.add);
  }
  ctx->SendAsync(
      ctx->NextRank(),
      ByteContainerView(send_msgs.data(), send_msgs.size() * sizeof(uint128_t)),
      "MpVole_msg");
}

void MpfssRecv(const std::shared_ptr<link::Context>& ctx,
               const OtRecvStore& /*cot*/ recv_ot, const MpFssParam& param,
               absl::Span<uint128_t> output, const MpfssOp<uint128_t>& op) {
  YACL_ENFORCE(param.assumption_ == LpnNoiseAsm::RegularNoise);
  YACL_ENFORCE(output.size() >= param.mp_vole_size_);
  YACL_ENFORCE(recv_ot.Size() >= param.require_ot_num_);

  const auto& batch_num = param.noise_num_;
  const auto& batch_size = param.sp_vole_size_;
  const auto& last_batch_size = param.last_sp_vole_size_;
  const auto& indexes = param.indexes_;

  UninitAlignedVector<uint128_t> dpf_sum(batch_num, 0);

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
    ParaCrHashInplace_128(this_span);
    dpf_sum[i] =
        std::reduce(this_span.begin(), this_span.end(), dpf_sum[i], op.add);
  }

  auto recv_buff = ctx->Recv(ctx->NextRank(), "MpVole_msg");
  YACL_ENFORCE(static_cast<uint64_t>(recv_buff.size()) >=
               batch_num * sizeof(uint128_t));

  auto recv_msgs =
      absl::MakeSpan(reinterpret_cast<uint128_t*>(recv_buff.data()), batch_num);
  for (uint32_t i = 0; i < batch_num; ++i) {
    auto tmp = op.sub(recv_msgs[i], dpf_sum[i]);
    output[i * batch_size + indexes[i]] =
        op.add(output[i * batch_size + indexes[i]], tmp);
  }
}

void MpfssSend(const std::shared_ptr<link::Context>& ctx,
               const OtSendStore& /*cot*/ send_ot, const MpFssParam& param,
               absl::Span<const uint64_t> w, absl::Span<uint64_t> output,
               const MpfssOp<uint64_t>& op) {
  YACL_ENFORCE(param.assumption_ == LpnNoiseAsm::RegularNoise);
  YACL_ENFORCE(output.size() >= param.mp_vole_size_);
  YACL_ENFORCE(w.size() >= param.noise_num_);
  YACL_ENFORCE(send_ot.Size() >= param.require_ot_num_);

  const auto& batch_num = param.noise_num_;
  const auto& batch_size = param.sp_vole_size_;
  const auto& last_batch_size = param.last_sp_vole_size_;

  UninitAlignedVector<uint64_t> send_msgs(batch_num, 0);
  std::transform(send_msgs.cbegin(), send_msgs.cend(), w.cbegin(),
                 send_msgs.begin(), op.sub);

  auto dpf_buff =
      Buffer(std::max(batch_size, last_batch_size) * sizeof(uint128_t));
  auto dpf_span = absl::MakeSpan(dpf_buff.data<uint128_t>(),
                                 dpf_buff.size() / sizeof(uint128_t));
  // UninitAlignedVector<uint128_t> dpf_buff(std::max(batch_size,
  // last_batch_size));

  for (uint32_t i = 0; i < batch_num; ++i) {
    auto this_size = (i == batch_num - 1) ? last_batch_size : batch_size;
    auto this_span = dpf_span.subspan(0, this_size);

    // TODO: @wenfan
    // "Slice" would force to slice original OtStore from "begin" to "end",
    // which might cause unexpected error.
    // It would be better to use "NextSlice" here, but it's not a const
    // function.
    auto ot_slice = send_ot.Slice(
        i * math::Log2Ceil(batch_size),
        i * math::Log2Ceil(batch_size) + math::Log2Ceil(this_size));

    GywzOtExtSend(ctx, ot_slice, this_size, this_span);
    ParaCrHashInplace_128(this_span);

    // Break the correlation
    std::transform(
        this_span.begin(), this_span.end(), output.data() + i * batch_size,
        [](const uint128_t& val) { return static_cast<uint64_t>(val); });

    send_msgs[i] = std::reduce(output.data() + i * batch_size,
                               output.data() + i * batch_size + this_size,
                               send_msgs[i], op.add);
  }
  ctx->SendAsync(
      ctx->NextRank(),
      ByteContainerView(send_msgs.data(), send_msgs.size() * sizeof(uint64_t)),
      "MpVole_msg");
}

void MpfssRecv(const std::shared_ptr<link::Context>& ctx,
               const OtRecvStore& /*cot*/ recv_ot, const MpFssParam& param,
               absl::Span<uint64_t> output, const MpfssOp<uint64_t>& op) {
  YACL_ENFORCE(param.assumption_ == LpnNoiseAsm::RegularNoise);
  YACL_ENFORCE(output.size() >= param.mp_vole_size_);
  YACL_ENFORCE(recv_ot.Size() >= param.require_ot_num_);

  const auto& batch_num = param.noise_num_;
  const auto& batch_size = param.sp_vole_size_;
  const auto& last_batch_size = param.last_sp_vole_size_;
  const auto& indexes = param.indexes_;

  auto dpf_buf =
      Buffer(std::max(batch_size, last_batch_size) * sizeof(uint128_t));
  auto dpf_span = absl::MakeSpan(dpf_buf.data<uint128_t>(),
                                 dpf_buf.size() / sizeof(uint128_t));

  UninitAlignedVector<uint64_t> dpf_sum(batch_num, 0);

  for (uint32_t i = 0; i < batch_num; ++i) {
    auto this_size = (i == batch_num - 1) ? last_batch_size : batch_size;
    auto this_span = dpf_span.subspan(0, this_size);

    // TODO: @wenfan
    // "Slice" would force to slice original OtStore from "begin" to "end",
    // which might cause unexpected error.
    // It would be better to use "NextSlice" here, but it's not a const
    // function.
    auto ot_slice = recv_ot.Slice(
        i * math::Log2Ceil(batch_size),
        i * math::Log2Ceil(batch_size) + math::Log2Ceil(this_size));
    GywzOtExtRecv(ctx, ot_slice, this_size, indexes[i], this_span);
    ParaCrHashInplace_128(this_span);

    std::transform(
        this_span.begin(), this_span.end(), output.data() + i * batch_size,
        [](const uint128_t& val) { return static_cast<uint64_t>(val); });
    dpf_sum[i] = std::reduce(output.data() + i * batch_size,
                             output.data() + i * batch_size + this_size,
                             dpf_sum[i], op.add);
  }

  auto recv_buff = ctx->Recv(ctx->NextRank(), "MpVole_msg");
  YACL_ENFORCE(static_cast<uint64_t>(recv_buff.size()) >=
               batch_num * sizeof(uint64_t));

  auto recv_msgs =
      absl::MakeSpan(reinterpret_cast<uint64_t*>(recv_buff.data()), batch_num);
  for (uint32_t i = 0; i < batch_num; ++i) {
    auto tmp = op.sub(recv_msgs[i], dpf_sum[i]);
    output[i * batch_size + indexes[i]] =
        op.add(output[i * batch_size + indexes[i]], tmp);
  }
}

void MpfssSend_fixed_index(const std::shared_ptr<link::Context>& ctx,
                           const OtSendStore& /*cot*/ send_ot,
                           MpFssParam& param, absl::Span<const uint128_t> w,
                           absl::Span<uint128_t> output,
                           const MpfssOp<uint128_t>& op) {
  YACL_ENFORCE(param.assumption_ == LpnNoiseAsm::RegularNoise);
  YACL_ENFORCE(output.size() >= param.mp_vole_size_);
  YACL_ENFORCE(w.size() >= param.noise_num_);
  YACL_ENFORCE(send_ot.Size() >= param.require_ot_num_);

  const auto& batch_num = param.noise_num_;
  const auto& batch_size = param.sp_vole_size_;
  const auto& last_batch_size = param.last_sp_vole_size_;
  const auto batch_length = math::Log2Ceil(batch_size);
  const auto last_batch_length = math::Log2Ceil(last_batch_size);

  // Copy vector w
  UninitAlignedVector<uint128_t> dpf_sum(batch_num, 0);
  std::transform(dpf_sum.cbegin(), dpf_sum.cend(), w.cbegin(), dpf_sum.begin(),
                 op.sub);
  // send message buff for GYWZ OTe
  auto gywz_send_msgs = UninitAlignedVector<uint128_t>(
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
      auto batch_idx = s * kSuperBatch + i;
      auto this_span = output.subspan(batch_idx * batch_size, this_size);

      // TODO: @wenfan
      // "Slice" would force to slice original OtStore from "begin" to "end",
      // which might cause unexpected error.
      // It would be better to use "NextSlice" here, but it's not a const
      auto ot_slice = send_ot.Slice(batch_idx * batch_length,
                                    batch_idx * batch_length + this_length);
      auto send_span =
          absl::MakeSpan(gywz_send_msgs.data() + i * batch_length, this_length);
      // GywzOtExt is single-point COT
      GywzOtExtSend_fixed_index(ot_slice, this_size, this_span, send_span);
      // Use CrHash to break the correlation
      ParaCrHashInplace_128(this_span);
      // this_span xor
      dpf_sum[batch_idx] = std::reduce(this_span.begin(), this_span.end(),
                                       dpf_sum[batch_idx], op.add);
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

  auto& send_msgs = dpf_sum;
  ctx->SendAsync(
      ctx->NextRank(),
      ByteContainerView(send_msgs.data(), send_msgs.size() * sizeof(uint128_t)),
      "MPVOLE:messages");
}

void MpfssRecv_fixed_index(const std::shared_ptr<link::Context>& ctx,
                           const OtRecvStore& /*cot*/ recv_ot,
                           MpFssParam& param, absl::Span<uint128_t> output,
                           const MpfssOp<uint128_t>& op) {
  YACL_ENFORCE(param.assumption_ == LpnNoiseAsm::RegularNoise);
  YACL_ENFORCE(output.size() >= param.mp_vole_size_);
  YACL_ENFORCE(recv_ot.Size() >= param.require_ot_num_);

  const auto& batch_num = param.noise_num_;
  const auto& batch_size = param.sp_vole_size_;
  const auto& last_batch_size = param.last_sp_vole_size_;
  const auto batch_length = math::Log2Ceil(batch_size);
  const auto last_batch_length = math::Log2Ceil(last_batch_size);

  auto& indexes = param.indexes_;

  const auto super_batch_num = math::DivCeil(batch_num, kSuperBatch);

  // Copy vector v
  auto dpf_sum = UninitAlignedVector<uint128_t>(batch_num, 0);

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
      auto batch_idx = s * kSuperBatch + i;
      auto this_span = output.subspan(batch_idx * batch_size, this_size);
      // TODO: @wenfan
      // "Slice" would force to slice original OtStore from "begin" to "end",
      // which might cause unexpected error.
      // It would be better to use "NextSlice" here, but it's not a const
      auto ot_slice = recv_ot.Slice(batch_idx * batch_length,
                                    batch_idx * batch_length + this_length);
      auto recv_span =
          absl::MakeSpan(gywz_recv_msgs.data() + i * batch_length, this_length);

      uint32_t real_index = 0;
      for (size_t i = 0; i < this_length; ++i) {
        real_index |= ot_slice.GetChoice(i) << i;
      }
      if (indexes[batch_idx] != real_index) {
        SPDLOG_DEBUG(
            "batch_idx {} , param.index_ ({}) and ot.choices mismatch ({}) !!!",
            batch_idx, indexes[batch_idx], real_index);
        indexes[batch_idx] = real_index;
      }
      // GywzOtExt is single-point COT
      GywzOtExtRecv_fixed_index(ot_slice, this_size, this_span, recv_span);
      // Use CrHash to break the correlation
      ParaCrHashInplace_128(this_span);
      // this_span xor
      dpf_sum[batch_idx] = std::reduce(this_span.begin(), this_span.end(),
                                       dpf_sum[batch_idx], op.add);
    }
  }

  // Break the correlation

  auto recv_buff = ctx->Recv(ctx->NextRank(), "MPVOLE:messages");
  YACL_ENFORCE(static_cast<uint64_t>(recv_buff.size()) ==
               batch_num * sizeof(uint128_t));
  auto recv_msgs =
      absl::MakeSpan(reinterpret_cast<uint128_t*>(recv_buff.data()), batch_num);

  for (uint32_t i = 0; i < batch_num; ++i) {
    auto tmp = op.sub(recv_msgs[i], dpf_sum[i]);
    output[i * batch_size + indexes[i]] =
        op.add(output[i * batch_size + indexes[i]], tmp);
  }
}

void MpfssSend_fixed_index(const std::shared_ptr<link::Context>& ctx,
                           const OtSendStore& /*cot*/ send_ot,
                           MpFssParam& param, absl::Span<const uint64_t> w,
                           absl::Span<uint64_t> output,
                           const MpfssOp<uint64_t>& op) {
  YACL_ENFORCE(param.assumption_ == LpnNoiseAsm::RegularNoise);
  YACL_ENFORCE(output.size() >= param.mp_vole_size_);
  YACL_ENFORCE(w.size() >= param.noise_num_);
  YACL_ENFORCE(send_ot.Size() >= param.require_ot_num_);

  const auto& batch_num = param.noise_num_;
  const auto& batch_size = param.sp_vole_size_;
  const auto& last_batch_size = param.last_sp_vole_size_;
  const auto batch_length = math::Log2Ceil(batch_size);
  const auto last_batch_length = math::Log2Ceil(last_batch_size);

  // copy w
  UninitAlignedVector<uint64_t> dpf_sum(batch_num, 0);
  std::transform(dpf_sum.cbegin(), dpf_sum.cend(), w.cbegin(), dpf_sum.begin(),
                 op.sub);
  // GywzOtExt need uint128_t buffer
  auto dpf_buf = Buffer((1 << std::max(batch_length, last_batch_length)) *
                        sizeof(uint128_t));
  // auto dpf_buf =
  //     UninitAlignedVector<uint128_t>(1 << std::max(batch_length,
  //     last_batch_length));
  auto dpf_span = absl::MakeSpan(dpf_buf.data<uint128_t>(),
                                 dpf_buf.size() / sizeof(uint128_t));
  // send message buffer for GYWZ OTe
  auto gywz_send_msgs = UninitAlignedVector<uint128_t>(
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
      // full_size = 1 << this_length, would avoid copying in GywzOtExt
      auto full_size = 1 << this_length;
      auto batch_idx = s * kSuperBatch + i;
      auto this_span = dpf_span.subspan(0, full_size);

      // TODO: @wenfan
      // "Slice" would force to slice original OtStore from "begin" to "end",
      // which might cause unexpected error.
      // It would be better to use "NextSlice" here, but it's not a const
      auto ot_slice = send_ot.Slice(batch_idx * batch_length,
                                    batch_idx * batch_length + this_length);
      auto send_span =
          absl::MakeSpan(gywz_send_msgs.data() + i * batch_length, this_length);
      // GywzOtExt is single-point COT
      GywzOtExtSend_fixed_index(ot_slice, full_size, this_span, send_span);
      // Use CrHash to break the correlation
      ParaCrHashInplace_128(this_span.subspan(0, this_size));
      // convert to uint64_t
      std::transform(this_span.begin(), this_span.begin() + this_size,
                     output.data() + batch_idx * batch_size,
                     [](uint128_t t) -> uint64_t { return t; });
      // this_span xor
      dpf_sum[batch_idx] =
          std::reduce(output.data() + batch_idx * batch_size,
                      output.data() + batch_idx * batch_size + this_size,
                      dpf_sum[batch_idx], op.add);
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

  auto& send_msgs = dpf_sum;
  ctx->SendAsync(
      ctx->NextRank(),
      ByteContainerView(send_msgs.data(), send_msgs.size() * sizeof(uint64_t)),
      "MPVOLE:messages");
}

void MpfssRecv_fixed_index(const std::shared_ptr<link::Context>& ctx,
                           const OtRecvStore& /*cot*/ recv_ot,
                           MpFssParam& param, absl::Span<uint64_t> output,
                           const MpfssOp<uint64_t>& op) {
  YACL_ENFORCE(param.assumption_ == LpnNoiseAsm::RegularNoise);
  YACL_ENFORCE(output.size() >= param.mp_vole_size_);
  YACL_ENFORCE(recv_ot.Size() >= param.require_ot_num_);

  const auto& batch_num = param.noise_num_;
  const auto& batch_size = param.sp_vole_size_;
  const auto& last_batch_size = param.last_sp_vole_size_;
  const auto batch_length = math::Log2Ceil(batch_size);
  const auto last_batch_length = math::Log2Ceil(last_batch_size);

  auto& indexes = param.indexes_;

  const auto super_batch_num = math::DivCeil(batch_num, kSuperBatch);

  auto dpf_sum = UninitAlignedVector<uint64_t>(batch_num, 0);
  // GywzOtExt need uint128_t buffer
  auto dpf_buf = Buffer((1 << std::max(batch_length, last_batch_length)) *
                        sizeof(uint128_t));
  // auto dpf_buf =
  //     UninitAlignedVector<uint128_t>(1 << std::max(batch_length,
  //     last_batch_length));
  auto dpf_span = absl::MakeSpan(dpf_buf.data<uint128_t>(),
                                 dpf_buf.size() / sizeof(uint128_t));

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
      // full_size = 1 << this_length, would avoid copying in GywzOtExt
      auto full_size = 1 << this_length;
      auto batch_idx = s * kSuperBatch + i;
      auto this_span = dpf_span.subspan(0, full_size);
      // TODO: @wenfan
      // "Slice" would force to slice original OtStore from "begin" to "end",
      // which might cause unexpected error.
      // It would be better to use "NextSlice" here, but it's not a const
      auto ot_slice = recv_ot.Slice(batch_idx * batch_length,
                                    batch_idx * batch_length + this_length);

      uint32_t real_index = 0;
      for (size_t i = 0; i < this_length; ++i) {
        real_index |= ot_slice.GetChoice(i) << i;
      }
      if (indexes[batch_idx] != real_index) {
        SPDLOG_DEBUG(
            "batch_idx {} , param.index_ ({}) and ot.choices mismatch ({}) !!!",
            batch_idx, indexes[batch_idx], real_index);
        indexes[batch_idx] = real_index;
      }

      auto recv_span =
          absl::MakeSpan(gywz_recv_msgs.data() + i * batch_length, this_length);
      // GywzOtExt is single-point COT
      GywzOtExtRecv_fixed_index(ot_slice, full_size, this_span, recv_span);
      // Use CrHash to break the correlation
      ParaCrHashInplace_128(this_span.subspan(0, this_size));
      // convert to uint64_t
      std::transform(this_span.begin(), this_span.begin() + this_size,
                     output.data() + batch_idx * batch_size,
                     [](uint128_t t) { return static_cast<uint64_t>(t); });
      // this_span xor
      dpf_sum[batch_idx] =
          std::reduce(output.data() + batch_idx * batch_size,
                      output.data() + batch_idx * batch_size + this_size,
                      dpf_sum[batch_idx], op.add);
    }
  }

  auto recv_buff = ctx->Recv(ctx->NextRank(), "MPVOLE:messages");
  YACL_ENFORCE(static_cast<uint64_t>(recv_buff.size()) ==
               batch_num * sizeof(uint64_t));
  auto recv_msgs =
      absl::MakeSpan(reinterpret_cast<uint64_t*>(recv_buff.data()), batch_num);

  for (uint32_t i = 0; i < batch_num; ++i) {
    auto tmp = op.sub(recv_msgs[i], dpf_sum[i]);
    output[i * batch_size + indexes[i]] =
        op.add(output[i * batch_size + indexes[i]], tmp);
  }
}

}  // namespace yacl::crypto
