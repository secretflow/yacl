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

#include "absl/types/span.h"

#include "yacl/base/int128.h"
#include "yacl/link/link.h"
#include "yacl/secparam.h"

/* submodules */
#include "yacl/crypto/aes/aes_opt.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/crypto/tools/crhash.h"
#include "yacl/crypto/tools/prg.h"
#include "yacl/kernel/algorithms/ot_store.h"

/* security parameter declaration */
YACL_MODULE_DECLARE("gywz_ote", SecParam::C::INF, SecParam::S::INF);

namespace yacl::crypto {
//
// GYWZ OT Extension (Half Tree) Implementation
//
// Implementation of (n-1)-out-of-n Correlated OT (also called single point
// COT, SpCot), for more theoretical details, see
// https://eprint.iacr.org/2022/1431.pdf, Figure 3 and Figure 4.
//
//                 +---------+    +----------+
//                 |   COT   | => |  SP-COT  |
//                 +---------+    +----------+
//                   num = n         num = 1
//                  len = 128       len = 2^n
//
//  > 128 is the length of seed for PRG
//
// Security assumptions:
//   - Circular correlation-robust Hash, for more details
//     see yacl/crypto/tools/rp.h
//
void GywzOtExtRecv(const std::shared_ptr<link::Context>& ctx,
                   const OtRecvStore& cot, uint32_t n, uint32_t index,
                   absl::Span<uint128_t> output);

void GywzOtExtSend(const std::shared_ptr<link::Context>& ctx,
                   const OtSendStore& cot, uint32_t n,
                   absl::Span<uint128_t> output);

// --------------------------
//         Customized
// --------------------------
//
// [Warning] For ferretOTe only
// Random single-point COT, where punctured index is determined by cot choices
// The output for sender and receiver would be SAME, when punctured
// index is greater than n.
// So, please don't use "GywzOtExtRecv_ferret" and "GywzOtExtSend_ferret",
// unless you know what you are doing
void GywzOtExtRecv_ferret(const std::shared_ptr<link::Context>& ctx,
                          const OtRecvStore& cot, uint32_t n,
                          absl::Span<uint128_t> output);

// [Warning] For ferretOTe only
void GywzOtExtSend_ferret(const std::shared_ptr<link::Context>& ctx,
                          const OtSendStore& cot, uint32_t n,
                          absl::Span<uint128_t> output);

// Notice that:
//  > In such cases, punctured index would be the choice of cot
//  > punctured index might be greater than n
void GywzOtExtRecv_fixed_index(const std::shared_ptr<link::Context>& ctx,
                               const OtRecvStore& cot, uint32_t n,
                               absl::Span<uint128_t> output);

void GywzOtExtSend_fixed_index(const std::shared_ptr<link::Context>& ctx,
                               const OtSendStore& cot, uint32_t n,
                               absl::Span<uint128_t> output);

// non-interactive function, Receiver should receive "recv_msgs" from Sender
void GywzOtExtRecv_fixed_index(const OtRecvStore& cot, uint32_t n,
                               absl::Span<uint128_t> output,
                               absl::Span<uint128_t> recv_msgs);

// non-interactive function, Sender should send "send_msgs" to Receiver
void GywzOtExtSend_fixed_index(const OtSendStore& cot, uint32_t n,
                               absl::Span<uint128_t> output,
                               absl::Span<uint128_t> send_msgs);

}  // namespace yacl::crypto
