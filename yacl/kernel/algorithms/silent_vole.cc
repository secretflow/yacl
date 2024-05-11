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

#include "yacl/kernel/algorithms/silent_vole.h"

#include <algorithm>
#include <memory>

#include "yacl/base/aligned_vector.h"
#include "yacl/base/dynamic_bitset.h"
#include "yacl/base/int128.h"

namespace yacl::crypto {

namespace {

//  minimum distance for dual-LPN code
static std::map<CodeType, double> kMinDistanceRatio = {
    {CodeType::Silver5, 0.2}, {CodeType::Silver11, 0.2},
    {CodeType::ExAcc7, 0.05}, {CodeType::ExAcc11, 0.1},
    {CodeType::ExAcc21, 0.1}, {CodeType::ExAcc40, 0.2}};

template <typename T>
struct VoleParam {
  uint64_t vole_num_;   // vole num
  uint64_t code_size_;  // code size

  CodeType codetype_;       // code type, e.g. silver5
  LpnNoiseAsm assumption_;  // LPN noise assumption

  MpVoleParam mp_param_;  // mp vole parameter

  uint64_t base_vole_ot_num_;  // base vole (cot-based)
  uint64_t mp_vole_ot_num_;    // mp vole (cot/rot-based)
  uint64_t require_ot_num_;    // total ot num

  bool is_mal_{false};

  // Constructor
  VoleParam([[maybe_unused]] CodeType code, [[maybe_unused]] uint64_t vole_num,
            [[maybe_unused]] bool mal = false) {}

  VoleParam(CodeType code, uint64_t vole_num, uint64_t sec, bool mal = false) {
    codetype_ = code;
    is_mal_ = mal;
    vole_num_ = vole_num;
    assumption_ = LpnNoiseAsm::RegularNoise;

    // default
    uint64_t gap = 0;  // Silver Parameters
    uint64_t code_scaler = 2;
    // check
    YACL_ENFORCE(
        kMinDistanceRatio.count(code),
        "Error: could not found the minimum distance for current code.");
    double min_dist_ratio = kMinDistanceRatio[code];

    switch (codetype_) {
      case CodeType::Silver5:
        gap = 16;
        break;
      case CodeType::Silver11:
        gap = 32;
        break;
      default:
        break;
    }

    auto noise_num = GenRegNoiseWeight(min_dist_ratio, sec);
    // Note that: the size of SpVole must be greater than one.
    // because 1-out-of-1 Vole/OT is meaningless
    auto sp_vole_size =
        std::max(math::DivCeil(vole_num * code_scaler, noise_num),
                 static_cast<uint64_t>(2));
    auto mp_vole_size = sp_vole_size * noise_num + gap;

    // initialize parameters for MpVole
    mp_param_ = MpVoleParam(noise_num, mp_vole_size, assumption_, is_mal_);

    code_size_ = mp_param_.mp_vole_size_ / code_scaler;
    // base_vole + mp_vole
    base_vole_ot_num_ =
        mp_param_.base_vole_num_ * sizeof(T) * 8;  // base_vole (cot-based)
    mp_vole_ot_num_ = mp_param_.require_ot_num_;   // mp_vole (cot/rot-based)
    require_ot_num_ = base_vole_ot_num_ + mp_vole_ot_num_;
  }
};

// Get Dual LPN Encoder, e.g. SilverCode, ExAccCode, (ExConvCode)
template <typename T>
std::shared_ptr<LinearCodeInterface> GetEncoder(const VoleParam<T>& param) {
  std::shared_ptr<LinearCodeInterface> encoder{nullptr};

  const auto codetype = param.codetype_;
  const auto code_size = param.code_size_;
  const auto vole_num = param.vole_num_;
  const auto mp_vole_size = param.mp_param_.mp_vole_size_;

  switch (codetype) {
    // the size of SilverCode is ( code_size * 2, code_size )
    case CodeType::Silver5:
      encoder = std::make_shared<SilverCode>(code_size, 5);
      break;
    case CodeType::Silver11:
      encoder = std::make_shared<SilverCode>(code_size, 11);
      break;
    // the size of ExAccCode is ( code_size * 2, vole_num  )
    case CodeType::ExAcc7:
      encoder = std::make_shared<ExAccCode<7>>(vole_num, mp_vole_size);
      break;
    case CodeType::ExAcc11:
      encoder = std::make_shared<ExAccCode<11>>(vole_num, mp_vole_size);
      break;
    case CodeType::ExAcc21:
      encoder = std::make_shared<ExAccCode<21>>(vole_num, mp_vole_size);
      break;
    case CodeType::ExAcc40:
      encoder = std::make_shared<ExAccCode<40>>(vole_num, mp_vole_size);
      break;
    // TODO(@wenfan)
    // support ExConv Code
    default:
      break;
  }
  return encoder;
}

template <typename T, typename K>
void DualLpnEncode(const VoleParam<T>& param, absl::Span<K> in,
                   absl::Span<K> out) {
  auto encoder = GetEncoder(param);
  if (std::dynamic_pointer_cast<SilverCode>(encoder)) {
    const auto vole_num = param.vole_num_;
    // [Warning] code_size is greater than vole_num
    // thus, "out" does not have enough space to execute "DualEncode"
    std::dynamic_pointer_cast<SilverCode>(encoder)->DualEncodeInplace(in);
    memcpy(out.data(), in.data(), vole_num * sizeof(K));
  } else if (std::dynamic_pointer_cast<ExAccCodeInterface>(encoder)) {
    std::dynamic_pointer_cast<ExAccCodeInterface>(encoder)->DualEncode(in, out);
  } else {
    YACL_THROW("Did not implement");
  }
}

template <typename T, typename K>
void DualLpnEncode2(const VoleParam<T>& param, absl::Span<T> in0,
                    absl::Span<T> out0, absl::Span<K> in1, absl::Span<K> out1) {
  auto encoder = GetEncoder(param);
  if (std::dynamic_pointer_cast<SilverCode>(encoder)) {
    const auto vole_num = param.vole_num_;
    // [Warning] code_size is greater than vole_num
    // thus, "out" does not have enough space to execute "DualEncode2"
    std::dynamic_pointer_cast<SilverCode>(encoder)->DualEncodeInplace2(in0,
                                                                       in1);
    memcpy(out0.data(), in0.data(), vole_num * sizeof(T));
    memcpy(out1.data(), in1.data(), vole_num * sizeof(K));
  } else if (std::dynamic_pointer_cast<ExAccCodeInterface>(encoder)) {
    std::dynamic_pointer_cast<ExAccCodeInterface>(encoder)->DualEncode2(
        in0, out0, in1, out1);
  } else {
    YACL_THROW("Did not implement");
  }
}

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
  if (!is_inited_) {
    OneTimeSetup(ctx);
  }

  const auto vole_num = c.size();
  auto param = VoleParam<T>(
      codetype_, vole_num, YACL_MODULE_SECPARAM_C_UINT("silent_vole"), is_mal_);
  auto& mp_param = param.mp_param_;

  // [Warning] copy, low efficiency
  auto all_cot = ss_sender_.GenCot(ctx, param.require_ot_num_);  // generate Cot
  auto mp_vole_cot = all_cot.NextSlice(param.mp_vole_ot_num_);   // mp-vole
  auto base_vole_cot = all_cot.NextSlice(param.base_vole_ot_num_);  // base-vole

  // base vole, w = u * delta + v
  std::vector<K> w(mp_param.base_vole_num_);
  Ot2VoleSend<T, K>(base_vole_cot, absl::MakeSpan(w));

  // mp vole
  auto mpvole = MpVoleSender<T, K>(mp_param);
  // w would be moved into mpvole
  mpvole.OneTimeSetup(static_cast<K>(delta_), std::move(w));
  // mp_vole output
  // UninitAlignedVector<K> mp_vole_output(mp_param.mp_vole_size_);
  auto buf = Buffer(mp_param.mp_vole_size_ * sizeof(K));
  auto mp_vole_output = absl::MakeSpan(buf.data<K>(), mp_param.mp_vole_size_);
  // mpvole with fixed index
  // which means punctured index would be determined by mp_vole_cot choices
  mpvole.Send(ctx, mp_vole_cot, mp_vole_output, true);
  // dual LPN
  // compressing mp_vole_output into c
  DualLpnEncode(param, mp_vole_output, c);
}

template <typename T, typename K>
void SilentVoleReceiver::RecvImpl(const std::shared_ptr<link::Context>& ctx,
                                  absl::Span<T> a, absl::Span<K> b) {
  if (!is_inited_) {
    OneTimeSetup(ctx);
  }

  const auto vole_num = a.size();
  YACL_ENFORCE(vole_num == b.size());
  auto param = VoleParam<T>(
      codetype_, vole_num, YACL_MODULE_SECPARAM_C_UINT("silent_vole"), is_mal_);
  auto& mp_param = param.mp_param_;

  // generate punctured indexes for MpVole
  mp_param.GenIndexes();
  // convert MpVole indexes to ot choices
  auto choices = mp_param.GenChoices();  // size param.mp_vole_ot_num_
  // generate the choices of base VOLE
  auto base_choices =
      SecureRandBits<dynamic_bitset<uint128_t>>(param.base_vole_ot_num_);
  // append choices and base_vole_choices
  choices.append(base_choices);

  // [Warning] copy, low efficiency
  auto all_cot = ss_receiver_.GenCot(ctx, choices);  // generate Cot by choices
  auto mp_vole_cot = all_cot.NextSlice(param.mp_vole_ot_num_);      // mp vole
  auto base_vole_cot = all_cot.NextSlice(param.base_vole_ot_num_);  // base vole

  // base vole, w = u * delta + v
  std::vector<T> u(mp_param.base_vole_num_);
  std::vector<K> v(mp_param.base_vole_num_);

  // base (subfield) VOLE
  Ot2VoleRecv<T, K>(base_vole_cot, absl::MakeSpan(u), absl::MakeSpan(v));

  // mp vole
  auto mpvole = MpVoleReceiver<T, K>(mp_param);
  // u && v would be moved into mpvole
  mpvole.OneTimeSetup(std::move(u), std::move(v));
  // sparse_noise && mp_vole output
  UninitAlignedVector<T> sparse_noise(mp_param.mp_vole_size_);
  // UninitAlignedVector<K> mp_vole_output(mp_param.mp_vole_size_);
  auto buf = Buffer(mp_param.mp_vole_size_ * sizeof(K));
  auto mp_vole_output = absl::MakeSpan(buf.data<K>(), mp_param.mp_vole_size_);
  // mpvole with fixed index
  // which means punctured index would be determined by mp_vole_cot choices
  mpvole.Recv(ctx, mp_vole_cot, absl::MakeSpan(sparse_noise), mp_vole_output,
              true);
  // dual LPN
  // compressing sparse_noise into a, mp_vole_output into b
  DualLpnEncode2(param, absl::MakeSpan(sparse_noise), a, mp_vole_output, b);
}

}  // namespace yacl::crypto
