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

#include <cstddef>

#include "absl/types/span.h"

#include "yacl/crypto/primitives/ot/common.h"
#include "yacl/link/link.h"

namespace yacl::crypto {

// IknpOtExtSend IknpOtExtRecv
//
// About raw IKNP OT Extension.
// See charpter 2 in https://eprint.iacr.org/2016/799.pdf
//
// For random OT, there is bandwidth optimized OT extension.
// See <<More Efficient Oblivious Transfer and Extensions for Faster Secure
// Computation>> @ https://eprint.iacr.org/2013/552.pdf (Protocol 52)
//
// This file implements the optimized random OT Extension, which is the optimal
// way to generate AND triple for GMW circuits.
//
// NOTE
//  * OT Extension sender requires receiver base ot context.
//  * OT Extension receiver requires sender base ot context.
//
// For a general random OT extension. Usually we perform OT extension with l ==
// 128. Then each side could get a AES key and can extend to any |l| size
// message that is bigger than 128. In GMW, the special point is the string
// length l is 1, but to break correlation. We still need a bigger k, such as 80
// or 128.
//
// NOTE |choices| need to be round up to 128.
void IknpOtExtSend(const std::shared_ptr<link::Context>& ctx,
                   const BaseOtRecvStore& base_options,
                   absl::Span<std::array<uint128_t, 2>> send_blocks);

// TODO(shuyan.ycf): replaces `choices` with strong-typed bit vector.
void IknpOtExtRecv(const std::shared_ptr<link::Context>& ctx,
                   const BaseOtSendStore& base_options,
                   absl::Span<const uint128_t> choices,
                   absl::Span<uint128_t> recv_blocks);

}  // namespace yacl::crypto