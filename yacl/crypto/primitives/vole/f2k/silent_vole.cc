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

#include "yacl/crypto/primitives/vole/f2k/silent_vole.h"

#include <type_traits>

#include "yacl/base/aligned_vector.h"
#include "yacl/base/dynamic_bitset.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/primitives/ot/ferret_ote.h"
#include "yacl/crypto/primitives/vole/f2k/base_vole.h"
#include "yacl/crypto/primitives/vole/f2k/sparse_vole.h"
#include "yacl/crypto/tools/code_interface.h"
#include "yacl/crypto/tools/expand_accumulate_code.h"
#include "yacl/crypto/tools/silver_code.h"
#include "yacl/crypto/utils/rand.h"
#include "yacl/math/gadget.h"

namespace yacl::crypto {

namespace {

uint64_t GenRegNoiseWeight(double min_dist_ratio, uint64_t sec) {
  if (min_dist_ratio > 0.5 || min_dist_ratio <= 0) {
    YACL_THROW("mini distance too small, rate {}", min_dist_ratio);
  }

  auto d = std::log2(1 - 2 * min_dist_ratio);
  auto t = std::max<uint64_t>(128, -double(sec) / d);

  return math::RoundUpTo(t, 8);
}

// Silent Vole internal parameters
template <typename T, typename K>
struct VoleParam {
  uint64_t vole_num_;   // vole num
  uint64_t code_size_;  // code size

  CodeType codetype_;       // code type, e.g. silver5
  LpnNoiseAsm assumption_;  // LPN noise assumption

  MpVoleParam mp_param_;  // mp vole parameter

  uint64_t base_vole_ot_num_;  // base vole (cot-based)
  uint64_t mp_vole_ot_num_;    // mp vole (cot/rot-based)
  uint64_t require_ot_num_;    // total ot num

  // dual-LPN encoder: SilverCode, ExAccCode, or (ExConvCode)
  std::shared_ptr<LinearCodeInterface> encoder_{nullptr};

  VoleParam(CodeType code, uint64_t vole_num, uint64_t sec = 128) {
    // default
    uint64_t gap = 0;
    uint64_t code_scaler = 2;
    double min_dist_ratio = 0.2;
    codetype_ = code;

    switch (codetype_) {
      case CodeType::Silver5:
        gap = 16;
        break;
      case CodeType::Silver11:
        gap = 32;
        break;
      case CodeType::ExAcc7:
        min_dist_ratio = 0.05;
        break;
      case CodeType::ExAcc11:
      case CodeType::ExAcc21:
        min_dist_ratio = 0.1;
        break;
      case CodeType::ExAcc40:
        min_dist_ratio = 0.2;
        break;
      // TODO: @wenfan
      // support ExConv Code
      default:
        break;
    }

    vole_num_ = vole_num;
    assumption_ = LpnNoiseAsm::RegularNoise;

    auto noise_num = GenRegNoiseWeight(min_dist_ratio, sec);
    // Note that: the size of SpVole must be greater than one.
    // because 1-out-of-1 Vole/OT is meaningless
    auto sp_vole_size =
        std::max(math::DivCeil(vole_num * code_scaler, noise_num),
                 static_cast<uint64_t>(2));
    auto mp_vole_size = sp_vole_size * noise_num + gap;

    mp_param_ = MpVoleParam(noise_num, mp_vole_size, assumption_);

    code_size_ = mp_param_.mp_vole_size_ / code_scaler;
    // base_vole + mp_vole
    base_vole_ot_num_ =
        mp_param_.noise_num_ * sizeof(T) * 8;     // base_vole (cot-based)
    mp_vole_ot_num_ = mp_param_.require_ot_num_;  // mp_vole (cot/rot-based)
    require_ot_num_ = base_vole_ot_num_ + mp_vole_ot_num_;

    // initialize encoder
    switch (codetype_) {
      // the size of SilverCode is ( code_size_ * 2 x code_size_ )
      case CodeType::Silver5:
        encoder_ = std::make_shared<SilverCode>(code_size_, 5);
        break;
      case CodeType::Silver11:
        encoder_ = std::make_shared<SilverCode>(code_size_, 11);
        break;
      // the size of ExAccCode is ( code_size_ * 2 x vole_num_ )
      case CodeType::ExAcc7:
        encoder_ =
            std::make_shared<ExAccCode<7>>(vole_num_, mp_param_.mp_vole_size_);
        break;
      case CodeType::ExAcc11:
        encoder_ =
            std::make_shared<ExAccCode<11>>(vole_num_, mp_param_.mp_vole_size_);
        break;
      case CodeType::ExAcc21:
        encoder_ =
            std::make_shared<ExAccCode<21>>(vole_num_, mp_param_.mp_vole_size_);
        break;
      case CodeType::ExAcc40:
        encoder_ =
            std::make_shared<ExAccCode<40>>(vole_num_, mp_param_.mp_vole_size_);
        break;
      // TODO: @wenfan
      // support ExConv Code
      default:
        break;
    }
  }

  AlignedVector<T> GetSparseNoise(absl::Span<const T> noise) {
    YACL_ENFORCE(noise.size() >= mp_param_.noise_num_);
    AlignedVector<T> sparse_noise(mp_param_.mp_vole_size_, 0);

    if (mp_param_.indexes_.empty()) {
      mp_param_.GenIndexes();  // generate indexes for mp vole
    }

    for (uint32_t i = 0; i < mp_param_.noise_num_; ++i) {
      sparse_noise[i * mp_param_.sp_vole_size_ + mp_param_.indexes_[i]] =
          noise[i];
    }
    return sparse_noise;
  }

  void dualLPN(absl::Span<K> in, absl::Span<K> out) const {
    if (std::dynamic_pointer_cast<SilverCode>(encoder_)) {
      // [Warning] code_size_ is greater than vole_num_
      // thus, "out" does not have enough space to execute "DualEncode"
      std::dynamic_pointer_cast<SilverCode>(encoder_)->DualEncodeInplace(in);
      memcpy(out.data(), in.data(), vole_num_ * sizeof(K));
    } else if (std::dynamic_pointer_cast<ExAccCodeInterface>(encoder_)) {
      std::dynamic_pointer_cast<ExAccCodeInterface>(encoder_)->DualEncode(in,
                                                                          out);
    } else {
      YACL_THROW("Did not implement");
    }
  }

  void dualLPN2(absl::Span<T> in0, absl::Span<T> out0, absl::Span<K> in1,
                absl::Span<K> out1) const {
    if (std::dynamic_pointer_cast<SilverCode>(encoder_)) {
      // [Warning] code_size_ is greater than vole_num_
      // thus, "out" does not have enough space to execute "DualEncode2"
      std::dynamic_pointer_cast<SilverCode>(encoder_)->DualEncodeInplace2(in0,
                                                                          in1);
      memcpy(out0.data(), in0.data(), vole_num_ * sizeof(T));
      memcpy(out1.data(), in1.data(), vole_num_ * sizeof(K));
    } else if (std::dynamic_pointer_cast<ExAccCodeInterface>(encoder_)) {
      std::dynamic_pointer_cast<ExAccCodeInterface>(encoder_)->DualEncode2(
          in0, out0, in1, out1);
    } else {
      YACL_THROW("Did not implement");
    }
  }
};

}  // namespace

#define REGISTER_VOLE(type)                                                \
  void SilentVoleSender::Send(const std::shared_ptr<link::Context>& ctx,   \
                              absl::Span<type> c) {                        \
    SendImpl<type, type>(ctx, c);                                          \
  }                                                                        \
  void SilentVoleReceiver::Recv(const std::shared_ptr<link::Context>& ctx, \
                                absl::Span<type> a, absl::Span<type> b) {  \
    RecvImpl<type, type>(ctx, a, b);                                       \
  }

REGISTER_VOLE(uint64_t);
REGISTER_VOLE(uint128_t);
#undef REGISTER_VOLE

void SilentVoleSender::SfSend(const std::shared_ptr<link::Context>& ctx,
                              absl::Span<uint128_t> c) {
  SendImpl<uint64_t, uint128_t>(ctx, c);
}

void SilentVoleReceiver::SfRecv(const std::shared_ptr<link::Context>& ctx,
                                absl::Span<uint64_t> a,
                                absl::Span<uint128_t> b) {
  RecvImpl<uint64_t, uint128_t>(ctx, a, b);
}

template <typename T, typename K>
void SilentVoleSender::SendImpl(const std::shared_ptr<link::Context>& ctx,
                                absl::Span<K> c) {
  if (is_inited_ == false) {
    OneTimeSetup(ctx);
  }

  const auto vole_num = c.size();
  auto param = VoleParam<T, K>(codetype_, vole_num, 128);

  // [Warning] copy, low efficiency
  auto all_cot = ss_sender_.GenCot(ctx, param.require_ot_num_);
  auto mp_vole_cot = all_cot.NextSlice(param.mp_vole_ot_num_);      // mp-vole
  auto base_vole_cot = all_cot.NextSlice(param.base_vole_ot_num_);  // base-vole

  // base vole, w = u * delta + v
  AlignedVector<K> w(param.mp_param_.noise_num_);

  Ot2VoleSend<T, K>(base_vole_cot, absl::MakeSpan(w));

  // mp vole
  AlignedVector<K> mp_vole_output(param.mp_param_.mp_vole_size_);
  MpVoleSend_fixindex(ctx, mp_vole_cot, param.mp_param_, absl::MakeSpan(w),
                      absl::MakeSpan(mp_vole_output));
  // dual LPN
  // compressing mp_vole_output into c
  param.dualLPN(absl::MakeSpan(mp_vole_output), c);
}

template <typename T, typename K>
void SilentVoleReceiver::RecvImpl(const std::shared_ptr<link::Context>& ctx,
                                  absl::Span<T> a, absl::Span<K> b) {
  if (is_inited_ == false) {
    OneTimeSetup(ctx);
  }

  const auto vole_num = a.size();
  YACL_ENFORCE(vole_num == b.size());
  auto param = VoleParam<T, K>(codetype_, vole_num, 128);

  auto choices = RandBits<dynamic_bitset<uint128_t>>(param.require_ot_num_);
  // generate punctured indexes for MpVole
  param.mp_param_.GenIndexes();
  // set mp-cot choices by punctured indexes
  uint64_t pos = 0;
  for (size_t i = 0; i < param.mp_param_.noise_num_; ++i) {
    auto this_size = (i == param.mp_param_.noise_num_ - 1)
                         ? math::Log2Ceil(param.mp_param_.last_sp_vole_size_)
                         : math::Log2Ceil(param.mp_param_.sp_vole_size_);
    uint32_t bound = 1 << this_size;
    for (uint32_t mask = 1; mask < bound; mask <<= 1) {
      choices.set(pos, param.mp_param_.indexes_[i] & mask);
      ++pos;
    }
  }

  // [Warning] copy, low efficiency
  auto all_cot = ss_receiver_.GenCot(ctx, choices);
  auto mp_vole_cot = all_cot.NextSlice(param.mp_vole_ot_num_);      // mp vole
  auto base_vole_cot = all_cot.NextSlice(param.base_vole_ot_num_);  // base vole

  // base vole, w = u * delta + v
  AlignedVector<T> u(param.mp_param_.noise_num_);
  AlignedVector<K> v(param.mp_param_.noise_num_);

  // VOLE or subfield VOLE
  Ot2VoleRecv<T, K>(base_vole_cot, absl::MakeSpan(u), absl::MakeSpan(v));

  // mp vole
  auto sparse_e = param.GetSparseNoise(absl::MakeSpan(u));
  AlignedVector<K> mp_vole_output(param.mp_param_.mp_vole_size_);
  MpVoleRecv_fixindex(ctx, mp_vole_cot, param.mp_param_, absl::MakeSpan(v),
                      absl::MakeSpan(mp_vole_output));

  // dual LPN
  // compressing sparse_e into a, mp_vole_output into b
  param.dualLPN2(absl::MakeSpan(sparse_e), a, absl::MakeSpan(mp_vole_output),
                 b);
}

}  // namespace yacl::crypto
