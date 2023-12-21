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

#include <cstdint>
#include <memory>
#include <unordered_map>
#include <vector>

#include "yacl/crypto/primitives/ot/ot_store.h"
#include "yacl/crypto/utils/secparam.h"
#include "yacl/math/gadget.h"
#include "yacl/utils/cuckoo_index.h"
namespace yacl::crypto {

// Ferret OT Extension Implementation
//
// This implementation bases on Ferret OTE, for more theoretical details, see
// https://eprint.iacr.org/2020/924.pdf, section 6, figure 9. Note that our
// implementation is not exactly the same since original protocol uses ideal ot
// functionality (not random ot).
//
//              +---------+    +---------+
//              |   COT   | => |   COT   |
//              +---------+    +---------+
//              num = m*       num = n
//              len = kappa    len = kappa
//
//  > kappa: computation security parameter (128 for example)
//  > We provide a function `MakeFerretOtExtOption` to help user to calculate
//  the required cot numbers with his/her desired cot numbers.
//
// Security assumptions:
//  > Correlation-robust hash function, for more details about its
//  implementation, see `yacl/crypto-tools/rp.h`
// > Primal LPN, for more details, please see the original paper

uint64_t FerretCotHelper(const LpnParam& lpn_param, uint64_t ot_num);

OtSendStore FerretOtExtSend(const std::shared_ptr<link::Context>& ctx,
                            const OtSendStore& base_cot,
                            const LpnParam& lpn_param, uint64_t ot_num);

OtRecvStore FerretOtExtRecv(const std::shared_ptr<link::Context>& ctx,
                            const OtRecvStore& base_cot,
                            const LpnParam& lpn_param, uint64_t ot_num);

//
// --------------------------
//         Customized
// --------------------------
//
// [Warning] for cheetah only
void FerretOtExtSend_cheetah(const std::shared_ptr<link::Context>& ctx,
                             const OtSendStore& base_cot,
                             const LpnParam& lpn_param, uint64_t ot_num,
                             absl::Span<uint128_t> out);

void FerretOtExtRecv_cheetah(const std::shared_ptr<link::Context>& ctx,
                             const OtRecvStore& base_cot,
                             const LpnParam& lpn_param, uint64_t ot_num,
                             absl::Span<uint128_t> out);
}  // namespace yacl::crypto
