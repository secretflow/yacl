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

#include "yacl/crypto/primitives/ot/gywz_ote.h"
#include "yacl/crypto/primitives/ot/ot_store.h"
#include "yacl/crypto/utils/rand.h"
#include "yacl/link/link.h"

namespace yacl::crypto {

//
// GYWZ OT Extension (Half Tree) Implementation
//
// Implementation of (n-1)-out-of-n Correlated OT (also called single point COT
// ), for more theoretical details, see https://eprint.iacr.org/2022/1431.pdf,
// Figure 3 and Figure 4.
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
//     see yacl/crypto/tools/random_permutation.h
//

void GywzOtExtRecv(const std::shared_ptr<link::Context>& ctx,
                   const OtRecvStore& cot, uint32_t n, uint32_t index,
                   absl::Span<uint128_t> output);

void GywzOtExtSend(const std::shared_ptr<link::Context>& ctx,
                   const OtSendStore& cot, uint32_t n,
                   absl::Span<uint128_t> output);

// [Warning] For ferretOTe only
// Random single-point COT, where punctured index is determined by cot choices
// The output for sender and receiver would be SAME, when punctured
// index is greater than n.
// So, please don't use "FerretGywzOtExtRecv" and "FerretGywzOtExtSend", unless
// you know what you are doing
void FerretGywzOtExtRecv(const std::shared_ptr<link::Context>& ctx,
                         const OtRecvStore& cot, uint32_t n,
                         absl::Span<uint128_t> output);

// [Warning] For ferretOTe only
void FerretGywzOtExtSend(const std::shared_ptr<link::Context>& ctx,
                         const OtSendStore& cot, uint32_t n,
                         absl::Span<uint128_t> output);

}  // namespace yacl::crypto
