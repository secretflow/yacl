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

#include <memory>
#include <utility>

#include "absl/types/span.h"

#include "yacl/base/dynamic_bitset.h"
#include "yacl/base/exception.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/primitives/ot/ot_store.h"
#include "yacl/crypto/utils/rand.h"
#include "yacl/link/context.h"
#include "yacl/link/link.h"

namespace yacl::crypto {

// SoftSpoken OT Extension Implementation
//
// This implementation bases on Softspoken OTE, for more theoretical details,
// see https://eprint.iacr.org/2022/192.pdf, figure 7 and figure 8.
// In our implementation, we choose repetition code as default code for subspace
// VOLE.
//
//                kappa/k instances    kappa/k instances
//    +---------+    +----------+    +------------------+    +-------+
//    |   ROT   | => |   PPRF   | => | small field VOLE | => |  COT  |
//    +---------+    +----------+    +------------------+    +-------+
//    num = kappa      N  = 2^k         num = kappa/k         num = n
//    len = kappa     len = kappa       len = n               len = kappa
//
//                 (one-time setup)
//              (a.k.a (N-1)-out-of-N OT)               (a.k.a subfield VOLE)
//
//  > k: Softspoken parameter (decide the instances and num for PPRF)
//  > kappa: computation security parameter (128 for example)
//
// Security assumptions:
//  *. correlation-robust hash function, for more details about its
//  implementation, see `yacl/crypto/tools/random_permutation.h`
//
// NOTE:
//  * OT Extension sender requires receiver base ot context.
//  * OT Extension receiver requires sender base ot context.
//  * Computation cost would be O(2^k/k).
//  * Communication for each OT needs 128/k bits.
//  * parameter k should be a small number (no greater than 10).
//  * k = 2, 4, 8 are recommended in the localhost, LAN, WAN setting
//  respectively.
// *  step = 64 for k = 1 or 2; step = 32 for k = 3 or 4.

class SoftspokenOtExtSender {
 public:
  SoftspokenOtExtSender(uint64_t k = 2, uint64_t step = 0);

  void OneTimeSetup(const std::shared_ptr<link::Context>& ctx);

  void OneTimeSetup(const std::shared_ptr<link::Context>& ctx,
                    const OtRecvStore& base_ot);

  // old-style interface
  void Send(const std::shared_ptr<link::Context>& ctx,
            absl::Span<std::array<uint128_t, 2>> send_blocks, bool cot = false);

  // [Warning] low efficiency
  void GenRot(const std::shared_ptr<link::Context>& ctx, uint64_t num_ot,
              OtSendStore* out);

  // [Warning] low efficiency
  void GenCot(const std::shared_ptr<link::Context>& ctx, uint64_t num_ot,
              OtSendStore* out);

  // OtStore-style interface
  // [Warning] low efficiency
  OtSendStore GenRot(const std::shared_ptr<link::Context>& ctx,
                     uint64_t num_ot);

  // OtStore-style interface
  // [Warning] low efficiency
  OtSendStore GenCot(const std::shared_ptr<link::Context>& ctx,
                     uint64_t num_ot);

  uint128_t GetDelta() const { return delta_; }

  uint64_t GetK() const { return k_; }

  uint64_t GetStep() const { return step_; }

  void SetStep(uint64_t step) { step_ = step; }

 private:
  void GenSfVole(absl::Span<uint128_t> hash_buff,
                 absl::Span<uint128_t> xor_buff, absl::Span<uint128_t> u,
                 absl::Span<uint128_t> V);

  uint128_t counter_{0};  // counter for seed refresh

  // Softspoken one time setup
  bool inited_{false};
  uint64_t k_;           // parameter k
  uint64_t pprf_num_;    // kKappa / k
  uint64_t pprf_range_;  // the number of leaves for single pprf
  AlignedVector<uint128_t> punctured_leaves_;  // leaves for all pprf
  AlignedVector<uint128_t> punctured_idx_;     // pprf punctured index
  uint128_t delta_;  // cot delta a.k.a the choices of base OT
  std::array<uint128_t, 128> p_idx_mask_;     // mask for punctured index
  AlignedVector<uint128_t> compress_leaves_;  // compressed pprf leaves
  uint64_t step_{32};                         // super batch size = step_ * 128
};

class SoftspokenOtExtReceiver {
 public:
  SoftspokenOtExtReceiver(uint64_t k = 2, uint64_t step = 0);

  void OneTimeSetup(const std::shared_ptr<link::Context>& ctx);

  void OneTimeSetup(const std::shared_ptr<link::Context>& ctx,
                    const OtSendStore& base_ot);

  // old-style interface
  void Recv(const std::shared_ptr<link::Context>& ctx,
            const dynamic_bitset<uint128_t>& choices,
            absl::Span<uint128_t> recv_blocks, bool cot = false);

  // [Warning] low efficiency
  void GenRot(const std::shared_ptr<link::Context>& ctx, uint64_t num_ot,
              OtRecvStore* out);

  // [Warning] low efficiency
  void GenCot(const std::shared_ptr<link::Context>& ctx, uint64_t num_ot,
              OtRecvStore* out);

  void GenCot(const std::shared_ptr<link::Context>& ctx,
              const dynamic_bitset<uint128_t>& choices, OtRecvStore* out);

  // OtStore-style interface
  // [Warning] low efficiency
  OtRecvStore GenRot(const std::shared_ptr<link::Context>& ctx,
                     uint64_t num_ot);

  // OtStore-style interface
  // [Warning] low efficiency
  OtRecvStore GenCot(const std::shared_ptr<link::Context>& ctx,
                     uint64_t num_ot);

  OtRecvStore GenCot(const std::shared_ptr<link::Context>& ctx,
                     const dynamic_bitset<uint128_t>& choices);

  uint64_t GetK() const { return k_; }

  uint64_t GetStep() const { return step_; }

  void SetStep(uint64_t step) { step_ = step; }

 private:
  // Generate Subfield VOLE
  void GenSfVole(uint128_t choice, absl::Span<uint128_t> xor_buff,
                 absl::Span<uint128_t> u, absl::Span<uint128_t> W);

  uint128_t counter_{0};  // counter for seed refresh

  // Softspoken one time setup
  bool inited_{false};
  uint64_t k_;                           // parameter k
  uint64_t pprf_num_;                    // kkappa / k
  uint64_t pprf_range_;                  // the number of leaves for single pprf
  AlignedVector<uint128_t> all_leaves_;  // leaves for all pprf
  uint64_t step_{32};                    // super batch size = step_ * 128
};

// Softspoken Ot Extension interface
inline void SoftspokenOtExtSend(
    const std::shared_ptr<link::Context>& ctx, const OtRecvStore& base_ot,
    absl::Span<std::array<uint128_t, 2>> send_blocks, uint64_t k = 2,
    bool cot = false) {
  auto ssSender = SoftspokenOtExtSender(k);
  ssSender.OneTimeSetup(ctx, base_ot);
  ssSender.Send(ctx, send_blocks, cot);
}

inline void SoftspokenOtExtRecv(const std::shared_ptr<link::Context>& ctx,
                                const OtSendStore& base_ot,
                                const dynamic_bitset<uint128_t>& choices,
                                absl::Span<uint128_t> recv_blocks,
                                uint64_t k = 2, bool cot = false) {
  auto ssReceiver = SoftspokenOtExtReceiver(k);
  ssReceiver.OneTimeSetup(ctx, base_ot);
  ssReceiver.Recv(ctx, choices, recv_blocks, cot);
}

}  // namespace yacl::crypto
