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

#include <vector>

/* submodules */
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/crypto/tools/common.h"
#include "yacl/kernel/algorithms/mpfss.h"
#include "yacl/kernel/algorithms/ot_store.h"
#include "yacl/math/f2k/f2k_utils.h"
#include "yacl/math/gadget.h"
#include "yacl/secparam.h"

YACL_MODULE_DECLARE("mp_vole", SecParam::C::INF, SecParam::S::INF);

namespace yacl::crypto {

using MpVoleParam = MpFssParam;

//
// Implementation about multi-point VOLE over GF(2^128). For more detail, see
// https://eprint.iacr.org/2019/1084.pdf protocol 4 & protocol 5.
//
//    +-----------+       +-----------+
//    |   MP-FSS  |   =>  |  Mp-VOLE  |
//    +-----------+       +-----------+
//       num = m             num = m
//      len = kappa         len = kappa
//
// > kappa: computation security parameter (128 for example)
//
// Consistency check is adapted from Ferret/Wolverine:
// 1) Ferret Consistency check: https://eprint.iacr.org/2020/924.pdf Fig.6 and
// Appendix C
// 2) Wolverine Cosisntency check: https://eprint.iacr.org/2020/925.pdf
// Fig.7
//
// Notice:
//  - MpVoleSender would get vector c; MpVoleReceiver would get vector a and
//  vector b, where a is a sparse vector (t-weight).
//  - Send && Recv would consume base-VOLE (pre_c_ = delta * pre_a_ + pre_b_ ).
//  Before invoking MpVoleSender::Send and MpVoleReceiver::Recv, caller needs
//  provide t base-VOLE by calling OneTimeSetup.
//

template <typename T, typename K>
class MpVoleSender {
 public:
  MpVoleSender(const MpVoleParam& param) : param_(param) {
    is_mal_ = param_.is_mal_;
  }

  MpVoleSender(uint64_t noise_num, uint64_t mp_vole_size, bool mal = false)
      : param_(noise_num, mp_vole_size, mal), is_mal_(mal) {}

  void OneTimeSetup(K delta, absl::Span<K> pre_c) {
    YACL_ENFORCE(param_.base_vole_num_ == pre_c.size());

    delta_ = delta;
    pre_c_ = std::vector<K>(pre_c.begin(), pre_c.end());
    is_setup_ = true;
    is_finish_ = false;
  }

  void OneTimeSetup(K delta, std::vector<K>&& pre_c) {
    YACL_ENFORCE(param_.base_vole_num_ == pre_c.size());

    delta_ = delta;
    pre_c_ = std::move(pre_c);
    is_setup_ = true;
    is_finish_ = false;
  }

  // Multi-Point VOLE
  // MpVoleSender.Send would set 'c' as a * delta + b.
  void Send(const std::shared_ptr<link::Context>& ctx,
            const OtSendStore& /*cot*/ send_ot, absl::Span<K> c,
            bool fixed_index = false) {
    YACL_ENFORCE(is_setup_ == true);
    YACL_ENFORCE(is_finish_ == false);
    YACL_ENFORCE(c.size() >= param_.mp_vole_size_);
    // Call MPFSS
    if (fixed_index) {
      MpfssSend_fixed_index(ctx, send_ot, param_, absl::MakeSpan(pre_c_), c);
    } else {
      MpfssSend(ctx, send_ot, param_, absl::MakeSpan(pre_c_), c);
    }

    if (is_mal_) {
      K seed = SyncSeedRecv(ctx);
      auto uhash =
          math::UniversalHash<K>(seed, c.subspan(0, param_.mp_vole_size_));

      auto buf = ctx->Recv(ctx->NextRank(), "MpVole:Malicious");
      YACL_ENFORCE(buf.size() == sizeof(K));
      auto payload = *reinterpret_cast<K*>(buf.data());

      uhash = uhash ^ math::GfMul(payload, delta_) ^
              pre_c_[param_.base_vole_num_ - 1];

      auto hash = Blake3(ByteContainerView(&uhash, sizeof(uhash)));
      ctx->SendAsync(ctx->NextRank(), ByteContainerView(hash),
                     "MpVole:Hash Value");
    }
    is_finish_ = true;
  }

 private:
  MpVoleParam param_;
  K delta_{0};
  std::vector<K> pre_c_;

  bool is_mal_{false};
  bool is_setup_{false};
  bool is_finish_{false};
};

template <typename T, typename K>
class MpVoleReceiver {
 public:
  MpVoleReceiver(const MpVoleParam& param) : param_(param) {
    is_mal_ = param_.is_mal_;
  }

  MpVoleReceiver(uint64_t noise_num, uint64_t mp_vole_size, bool mal = false)
      : param_(noise_num, mp_vole_size, mal), is_mal_(mal) {}

  void OneTimeSetup(absl::Span<T> pre_a, absl::Span<K> pre_b) {
    YACL_ENFORCE(param_.base_vole_num_ == pre_a.size());
    YACL_ENFORCE(param_.base_vole_num_ == pre_b.size());

    pre_a_ = std::vector<T>(pre_a.begin(), pre_a.end());
    pre_b_ = std::vector<K>(pre_b.begin(), pre_b.end());
    is_setup_ = true;
  }

  void OneTimeSetup(std::vector<T>&& pre_a, std::vector<K>&& pre_b) {
    YACL_ENFORCE(param_.base_vole_num_ == pre_a.size());
    YACL_ENFORCE(param_.base_vole_num_ == pre_b.size());

    pre_a_ = std::move(pre_a);
    pre_b_ = std::move(pre_b);
    is_setup_ = true;
  }

  // Multi-Point VOLE
  // MpVoleReceiver.Recv would set 'a' and 'b'
  // s.t. c = a * delta + b, where a is t-weight vector.
  void Recv(const std::shared_ptr<link::Context>& ctx,
            const OtRecvStore& /*cot*/ recv_ot, absl::Span<T> a,
            absl::Span<K> b, bool fixed_index = false) {
    YACL_ENFORCE(is_setup_ == true);
    YACL_ENFORCE(is_finish_ == false);
    YACL_ENFORCE(a.size() >= param_.mp_vole_size_);
    YACL_ENFORCE(b.size() >= param_.mp_vole_size_);
    // Call MPFSS
    if (fixed_index) {
      MpfssRecv_fixed_index(ctx, recv_ot, param_, b);
    } else {
      MpfssRecv(ctx, recv_ot, param_, b);
    }

    // reset a
    std::memset(a.data(), 0, a.size() * sizeof(T));
    std::vector<uint64_t> indexes(param_.noise_num_);
    for (size_t i = 0; i < indexes.size(); ++i) {
      auto index = i * param_.sp_vole_size_ + param_.indexes_[i];
      indexes[i] = index;
      // insert base-VOLE value
      a[index] = pre_a_[i];
      b[index] = b[index] ^ pre_b_[i];
    }

    if (is_mal_) {
      K seed = SyncSeedSend(ctx);
      auto uhash =
          math::UniversalHash<K>(seed, b.subspan(0, param_.mp_vole_size_));
      auto coef = math::ExtractHashCoef<K>(seed, indexes);
      // Notice that: Sender.uhash + Receiver.uhash = payload * delta
      auto payload = math::GfMul(absl::MakeSpan(coef),
                                 absl::MakeSpan(pre_a_.data(), indexes.size()));

      // mask uhash && payload by extra one VOLE correlation
      payload ^= pre_a_[param_.base_vole_num_ - 1];
      uhash ^= pre_b_[param_.base_vole_num_ - 1];

      ctx->SendAsync(ctx->NextRank(),
                     ByteContainerView(&payload, sizeof(payload)),
                     "MpVole:Malicious");

      auto hash = Blake3(ByteContainerView(&uhash, sizeof(uhash)));
      auto buf = ctx->Recv(ctx->NextRank(), "MpVole: Hash Value");
      YACL_ENFORCE(ByteContainerView(hash) == ByteContainerView(buf));
    }

    is_finish_ = true;
  }

 private:
  MpVoleParam param_;

  std::vector<T> pre_a_;
  std::vector<K> pre_b_;

  bool is_mal_{false};
  bool is_setup_{false};
  bool is_finish_{false};
};

}  // namespace yacl::crypto
