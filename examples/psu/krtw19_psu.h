// Copyright 2024 zhangwfjh
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
#include <vector>

#include "yacl/base/int128.h"
#include "yacl/link/link.h"
#include "yacl/math/f2k/f2k.h"
#include "yacl/secparam.h"

/* submodules */
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/kernel/algorithms/base_ot.h"
#include "yacl/kernel/algorithms/kkrt_ote.h"
#include "yacl/kernel/algorithms/softspoken_ote.h"

/* security parameter declaration */
YACL_MODULE_DECLARE("krtw_psu", SecParam::C::k128, SecParam::S::k40);

namespace examples::psu {

uint64_t Evaluate(const std::vector<uint64_t>& coeffs, uint64_t x);

std::vector<uint64_t> Interpolate(const std::vector<uint64_t>& xs,
                                  const std::vector<uint64_t>& ys);

// Scalable Private Set Union from Symmetric-Key Techniques
// https://eprint.iacr.org/2019/776.pdf (Figure 10)

void KrtwPsuSend(const std::shared_ptr<yacl::link::Context>& ctx,
                 const std::vector<uint128_t>& elem_hashes);

std::vector<uint128_t> KrtwPsuRecv(
    const std::shared_ptr<yacl::link::Context>& ctx,
    const std::vector<uint128_t>& elem_hashes);

}  // namespace examples::psu
