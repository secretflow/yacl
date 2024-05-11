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

#pragma once

#include "yacl/base/exception.h"
#include "yacl/base/int128.h"
#include "yacl/link/context.h"
#include "yacl/secparam.h"

/* submodules */
#include "yacl/crypto/rand/rand.h"
#include "yacl/kernel/algorithms/base_vole.h"
#include "yacl/kernel/algorithms/mp_vole.h"
#include "yacl/kernel/code/code_interface.h"
#include "yacl/kernel/code/ea_code.h"
#include "yacl/kernel/code/silver_code.h"

/* security parameter declaration */
YACL_MODULE_DECLARE("silent_vole", SecParam::C::k128, SecParam::S::INF);
namespace yacl::crypto {

// Silent Vector OLE Implementation
//
// Silent VOLE is a "framework" to generate Vector OLE correlation. First of
// all, it would generate a special correlation c' = a' * delta + b', where a'
// is a random t-weight vector. Then, apply dual-LPN to make vectors a', b' and
// c' to be "Uniformly Random", satisfying c = a * delta + b. For more details,
// see https://eprint.iacr.org/2019/1159.pdf, figure 3.
//
//   +-------+      +-----------+     +-----------+      +----------+
//   |  COT  |  =>  | Base-VOLE |  => |  Mp-VOLE  |  =>  |   VOLE   |
//   +-------+      +-----------+     +-----------+      +----------+
//    num = m*         num = t           num = m         num = n (>256)
//   len = kappa      len = kappa       len = kappa       len = kappa
//
//  > kappa: computation security parameter (128 for example)
//
// Security assumptions:
//  > OT extension functionality, for more details about its implementation, see
//  `yacl/kernel/algorithms/softspoken_ote.h`
//  > base VOLE and multi-point VOLE functionalities, for more details about its
//  implementation, see `yacl/kernel/algorithms/mp_vole.h`
//  > Dual LPN problem, for more details, please see the original papers
//    1) Silver (https://eprint.iacr.org/2021/1150.pdf) Most
//    efficiency, but not recommended to use due to its security flaw.
//    2) Expand Accumulate Code (https://eprint.iacr.org/2022/1014.pdf)
//    3) Expand Convolute Code (https://eprint.iacr.org/2023/882.pdf)
//
// Note that:
// > Silent Vole Receiver would get vector a and vector b; Silent Vole Sender
// would get delta and vector c, such that c = a * delta + b
// > Silent Vole aims to generate large amount of VOLE correlation, thus the
// length of a,b,c should be greater than 256 at least.
// > When small amount of VOLE correlation is needed (less than 256), use
// `GilboaVoleSend/GilboaVoleRecv` instead.

// dual-LPN code type
enum class CodeType {
  // Support Silver & ExAcc only
  Silver5,
  Silver11,
  ExAcc7,
  ExAcc11,
  ExAcc21,
  ExAcc40,
  // TODO: @wenfan
  // Support ExConv Code
  ExConv7x24,
  ExConv21x24
};

class SilentVoleSender {
 public:
  explicit SilentVoleSender(CodeType code, bool mal = false) {
    codetype_ = code;
    is_mal_ = mal;
    ss_sender_ = SoftspokenOtExtSender(2, is_mal_);
  }

  void OneTimeSetup(const std::shared_ptr<link::Context>& ctx) {
    if (!is_inited_) {
      ss_sender_.OneTimeSetup(ctx);
      delta_ = ss_sender_.GetDelta();
      is_inited_ = true;
    }
  }

  // c = a * delta + b
  void Send(const std::shared_ptr<link::Context>& ctx, absl::Span<uint128_t> c);

  void Send(const std::shared_ptr<link::Context>& ctx, absl::Span<uint64_t> c);

  // subfield VOLE c = a * delta + b,
  // where a is in GF(2^64), delta, b, c are in GF(2^128)
  void SfSend(const std::shared_ptr<link::Context>& ctx,
              absl::Span<uint128_t> c);

  // GetDelta would return 128 bits delta.
  // However, in the case of GF(2^64), the low 64 bits of delta is used
  // Thus, uint64_t delta64 = DecomposeUInt128(delta).second;
  uint128_t GetDelta() const {
    YACL_ENFORCE(
        is_inited_ == true,
        "Silent Vole Error: Could not get delta before one-time setup");
    return delta_;
  }

  // low 64 bits
  uint64_t GetDelta64() const { return DecomposeUInt128(GetDelta()).second; }

  CodeType GetCodeType() const { return codetype_; }

  void SetOTCounter(uint64_t counter) { ss_sender_.SetCounter(counter); }

 private:
  bool is_inited_{false};
  bool is_mal_{false};
  CodeType codetype_;
  uint128_t delta_{0};
  SoftspokenOtExtSender ss_sender_;

  template <typename T, typename K>
  void SendImpl(const std::shared_ptr<link::Context>& ctx, absl::Span<K> c);
};

class SilentVoleReceiver {
 public:
  explicit SilentVoleReceiver(CodeType code, bool mal = false) {
    codetype_ = code;
    is_mal_ = mal;
    ss_receiver_ = SoftspokenOtExtReceiver(2, is_mal_);
  }

  void OneTimeSetup(const std::shared_ptr<link::Context>& ctx) {
    if (!is_inited_) {
      ss_receiver_.OneTimeSetup(ctx);
      is_inited_ = true;
    }
  }

  // c = a * delta + b
  void Recv(const std::shared_ptr<link::Context>& ctx, absl::Span<uint128_t> a,
            absl::Span<uint128_t> b);

  void Recv(const std::shared_ptr<link::Context>& ctx, absl::Span<uint64_t> a,
            absl::Span<uint64_t> b);

  // subfield VOLE c = a * delta + b,
  // where a is belong to GF(2^64), delta, b, c is belong to GF(2^128)
  void SfRecv(const std::shared_ptr<link::Context>& ctx, absl::Span<uint64_t> a,
              absl::Span<uint128_t> b);

  CodeType GetCodeType() const { return codetype_; }

  void SetOTCounter(uint64_t counter) { ss_receiver_.SetCounter(counter); }

 private:
  bool is_inited_{false};
  bool is_mal_{false};
  CodeType codetype_;
  SoftspokenOtExtReceiver ss_receiver_;

  template <typename T, typename K>
  void RecvImpl(const std::shared_ptr<link::Context>& ctx, absl::Span<T> a,
                absl::Span<K> b);
};

}  // namespace yacl::crypto
