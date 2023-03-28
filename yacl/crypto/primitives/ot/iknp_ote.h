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

#pragma once

#include <memory>

#include "absl/types/span.h"

#include "yacl/base/dynamic_bitset.h"
#include "yacl/crypto/primitives/ot/ot_store.h"
#include "yacl/link/link.h"

namespace yacl::crypto {

// IKNP OT Extension Implementation
//
// This implementation bases on IKNP OTE, for more theoretical details, see
// https://www.iacr.org/archive/crypto2003/27290145/27290145.pdf, section 3,
// figure 1. Note that our implementation is not exactly the same since original
// protocol uses ideal ot functionality (not random ot).
//
//              +---------+    +---------+    +---------+
//              |   ROT   | => |   COT   | => |   ROT   |
//              +---------+    +---------+    +---------+
//              num = kappa    num = n        num = n
//              len = n        len = kappa    len = kappa
//
//  > kappa: computation security parameter (128 for example)
//
// Security assumptions:
//  *. correlation-robust hash function, for more details about its
//  implementation, see `yacl/crypto-tools/random_permutation.h`
//
// NOTE
//  * OT Extension sender requires receiver base ot context.
//  * OT Extension receiver requires sender base ot context.
//

void IknpOtExtSend(const std::shared_ptr<link::Context>& ctx,
                   const std::shared_ptr<OtRecvStore>& base_ot,
                   absl::Span<std::array<uint128_t, 2>> send_blocks,
                   bool cot = false);

void IknpOtExtRecv(const std::shared_ptr<link::Context>& ctx,
                   const std::shared_ptr<OtSendStore>& base_ot,
                   const dynamic_bitset<uint128_t>& choices,
                   absl::Span<uint128_t> recv_blocks, bool cot = false);

// ==================== //
//   Support OT Store   //
// ==================== //

inline std::shared_ptr<OtSendStore> IknpOtExtSend(
    const std::shared_ptr<link::Context>& ctx,
    const std::shared_ptr<OtRecvStore>& base_ot, uint32_t ot_num,
    bool cot = false) {
  std::vector<std::array<uint128_t, 2>> blocks(ot_num);
  IknpOtExtSend(ctx, base_ot, absl::MakeSpan(blocks), cot);
  auto ret = MakeOtSendStore(blocks);
  if (cot) {
    auto tmp_choice = base_ot->CopyChoice();
    ret->SetDelta(static_cast<uint128_t>(*tmp_choice.data()));
  }
  return ret;  // FIXME: Drop explicit copy
}

inline std::shared_ptr<OtRecvStore> IknpOtExtRecv(
    const std::shared_ptr<link::Context>& ctx,
    const std::shared_ptr<OtSendStore>& base_ot,
    const dynamic_bitset<uint128_t>& choices, uint32_t ot_num,
    bool cot = false) {
  std::vector<uint128_t> blocks(ot_num);
  IknpOtExtRecv(ctx, base_ot, choices, absl::MakeSpan(blocks), cot);
  return MakeOtRecvStore(choices, blocks);  // FIXME: Drop explicit copy
}

}  // namespace yacl::crypto
