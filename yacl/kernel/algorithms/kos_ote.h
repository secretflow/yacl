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
#include "yacl/kernel/algorithms/ot_store.h"
#include "yacl/link/link.h"
#include "yacl/secparam.h"

/* submodules */
#include "yacl/crypto/rand/rand.h"
#include "yacl/crypto/tools/crhash.h"
#include "yacl/crypto/tools/prg.h"
#include "yacl/crypto/tools/rp.h"

/* security parameter declaration */
YACL_MODULE_DECLARE("kos_ote", SecParam::C::k128, SecParam::S::k64);

namespace yacl::crypto {

// KOS OT Extension Implementation (Malicious Secure)
//
// This implementation bases on KOS OTE, for more theoretical details, see
// https://eprint.iacr.org/2015/546.pdf. A more detailed security analysis of
// KOS could be found at: https://eprint.iacr.org/2022/1371.pdf.
//
//                base ot       output ot
//              +---------+    +---------+
//              |   ROT   | => |   ROT   |
//              +---------+    +---------+
//              num = kappa    num = n
//              len = n        len = kappa
//
//  > kappa: computation security parameter (128 for example)
//
// [Remarks] Although in the original protocol we need base ROT with length
// equal to the number of extended ots, in our implementation we only need ROT
// with length equal to the size of prg seeds (e.g. 128 bit), and then apply prg
// to extend OT lengths.
//
// [WARNING] Our implementation of KOS is implemented with the latest security
// fix, for more detailed discussions, see:
// - KOS paper (with fix): https://eprint.iacr.org/2015/546.pdf
// - SoftSpokenOT https://eprint.iacr.org/2022/192
// - KOS security proof (asymptotic) https://eprint.iacr.org/2022/1371.pdf
//

void KosOtExtSend(const std::shared_ptr<link::Context>& ctx,
                  const OtRecvStore& base_ot,
                  absl::Span<std::array<uint128_t, 2>> send_blocks,
                  bool cot = false);

void KosOtExtRecv(const std::shared_ptr<link::Context>& ctx,
                  const OtSendStore& base_ot,
                  const dynamic_bitset<uint128_t>& choices,
                  absl::Span<uint128_t> recv_blocks, bool cot = false);

// ==================== //
//   Support OT Store   //
// ==================== //

inline OtSendStore KosOtExtSend(const std::shared_ptr<link::Context>& ctx,
                                const OtRecvStore& base_ot, uint32_t ot_num,
                                bool cot = false) {
  std::vector<std::array<uint128_t, 2>> blocks(ot_num);
  KosOtExtSend(ctx, base_ot, absl::MakeSpan(blocks), cot);
  auto ret = MakeOtSendStore(blocks);
  if (cot) {
    auto tmp_choice = base_ot.CopyChoice();
    ret.SetDelta(static_cast<uint128_t>(*tmp_choice.data()));
  }
  return ret;  // FIXME: Drop explicit copy
}

inline OtRecvStore KosOtExtRecv(const std::shared_ptr<link::Context>& ctx,
                                const OtSendStore& base_ot,
                                const dynamic_bitset<uint128_t>& choices,
                                uint32_t ot_num, bool cot = false) {
  std::vector<uint128_t> blocks(ot_num);
  KosOtExtRecv(ctx, base_ot, choices, absl::MakeSpan(blocks), cot);
  return MakeOtRecvStore(choices, blocks);  // FIXME: Drop explicit copy
}

}  // namespace yacl::crypto
