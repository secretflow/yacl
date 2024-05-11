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

#include "yacl/kernel/algorithms/ot_store.h"
#include "yacl/link/link.h"
#include "yacl/secparam.h"

/* submodules */
#include "yacl/crypto/aes/aes_opt.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/crypto/tools/crhash.h"
#include "yacl/crypto/tools/prg.h"
#include "yacl/crypto/tools/ro.h"
#include "yacl/crypto/tools/rp.h"

/* security parameter declaration */
YACL_MODULE_DECLARE("sgrr_ote", SecParam::C::INF, SecParam::S::INF);

namespace yacl::crypto {

// Implementation of (n-1)-out-of-n Random OT (also called oblivious punctured
// vector), paper: https://eprint.iacr.org/2019/1084.
//
// This implementation requires at least log2(n) pre-generated Random OTs, and
// outputs n/n-1 64 bits seeds (but we are defining it as 128 bits), also,
// currently n should be 2^i, in test, we use n = 2^5, 2^10 ,2^15, plus n needs
// to at least be 4.
// We adopt the newer consistency check of Softspoken, see
// https://eprint.iacr.org/2022/192.pdf Fig.14 for more detail.
//
// Does the size in bits matter when seeding a pseudo-random number generator?
// The rationale behind this is that a PRG's seed is understood as (some kind
// of) a secret key, which the attacker must not be able to know or choose in
// any threat model. Say we want a 128-bit security, we mean that the
// probability of an adversary can "guess" the correct seed is samller than
// 2^(-128).
//
// Therefore, if we want 128-bit security, we can set seed length = 128.
//
// Security assumptions:
//  - Correlation-robust Hash, but here we use two-key PRF with AES key
// scheduling to optimize CrHash, see yacl/crypto/aes/aes_opt.h for more
// details.
//
// Some Discussions in the community:
//  - https://crypto.stackexchange.com/questions/38039
//  - https://stackoverflow.com/questions/50402168
//

void SgrrOtExtRecv(const std::shared_ptr<link::Context>& ctx,
                   const OtRecvStore& base_ot, uint32_t n, uint32_t index,
                   absl::Span<uint128_t> output, bool mal = false);

void SgrrOtExtSend(const std::shared_ptr<link::Context>& ctx,
                   const OtSendStore& base_ot, uint32_t n,
                   absl::Span<uint128_t> output, bool mal = false);

//
// --------------------------
//         Customized
// --------------------------
//

// SgrrOtExtHelper would return the size of Buffer used in
// `SgrrOtExtRecv_fixed_index` and `SgrrOtExtRecv_fixed_index`.
uint64_t inline SgrrOtExtHelper(uint32_t n, bool mal = false) {
  const uint32_t ot_num = math::Log2Ceil(n);
  const uint64_t ot_msg_size = ot_num * sizeof(uint128_t) * 2;
  const uint64_t check_size = (mal ? 32 * 2 : 0);
  return ot_msg_size + check_size;
}

// Notice that:
//  > In such cases, punctured index would be the choice of cot, which means
//  punctured index might be greater than n.
//  > Before call `SgrrOtExtRecv_fixed_index` and `SgrrOtExtSend_fixed_index`,
//  it would be better to get Buffer's size by invoking `SgrrOtExtHelper`.
void SgrrOtExtRecv_fixed_index(const std::shared_ptr<link::Context>& ctx,
                               const OtRecvStore& base_ot, uint32_t n,
                               absl::Span<uint128_t> output, bool mal = false);

void SgrrOtExtSend_fixed_index(const std::shared_ptr<link::Context>& ctx,
                               const OtSendStore& base_ot, uint32_t n,
                               absl::Span<uint128_t> output, bool mal = false);

// non-interactive function, Receiver should receive "recv_msgs" from Sender
// TODO: use `ByteContainerView` instead.
void SgrrOtExtRecv_fixed_index(const OtRecvStore& base_ot, uint32_t n,
                               absl::Span<uint128_t> output,
                               absl::Span<const uint8_t> recv_buf,
                               bool mal = false);

// non-interactive function, Sender should send "send_msg" to Receiver
// TODO:
void SgrrOtExtSend_fixed_index(const OtSendStore& base_ot, uint32_t n,
                               absl::Span<uint128_t> output,
                               absl::Span<uint8_t> send_buf, bool mal = false);

}  // namespace yacl::crypto
