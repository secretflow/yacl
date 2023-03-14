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

#include "yacl/crypto/primitives/ot/ot_store.h"
#include "yacl/crypto/utils/rand.h"
#include "yacl/link/link.h"

namespace yacl::crypto {

// Implementation of (n-1)-out-of-n Random OT (also called oblivious punctured
// vector), paper: https://eprint.iacr.org/2019/1084.
//
// This implementation requires at least n pre-generated Random OTs, and outputs
// n/n-1 64 bits seeds (but we are defining it as 128 bits), also, currently n
// should be 2^i, in test, we use n = 2^5, 2^10 ,2^15, plus n needs to at least
// be 4
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
// Some Discussions in the community:
// https://crypto.stackexchange.com/questions/38039
// https://stackoverflow.com/questions/50402168

void SgrrOtExtRecv(const std::shared_ptr<link::Context>& ctx,
                   const std::shared_ptr<OtRecvStore>& base_ot, uint32_t n,
                   uint32_t index, absl::Span<uint128_t> output);

void SgrrOtExtSend(const std::shared_ptr<link::Context>& ctx,
                   const std::shared_ptr<OtSendStore>& base_ot, uint32_t n,
                   absl::Span<uint128_t> output);

}  // namespace yacl::crypto
