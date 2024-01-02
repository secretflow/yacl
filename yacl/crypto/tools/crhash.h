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

#include <vector>

#include "absl/types/span.h"

#include "yacl/base/int128.h"

/* submodules */
#include "yacl/crypto/tools/rp.h"

namespace yacl::crypto {

// Correlation Robust Hash function (Single Block input)
// See https://eprint.iacr.org/2019/074.pdf Sec 7.2
// CrHash = RP(x) ^ x
uint128_t CrHash_128(uint128_t x);

// parallel crhash for many blocks
std::vector<uint128_t> ParaCrHash_128(absl::Span<const uint128_t> x);

// inplace parallel crhash for many blocks
void ParaCrHashInplace_128(absl::Span<uint128_t> inout);

// Circular Correlation Robust Hash function (Single Block)
// See https://eprint.iacr.org/2019/074.pdf Sec 7.3
// CcrHash = RP(Sigma(x)) ^ Sigma(x)
// Sigma(x) = (x.left ^ x.right) || x.left
uint128_t CcrHash_128(uint128_t x);

// parallel ccrhash for many blocks
std::vector<uint128_t> ParaCcrHash_128(absl::Span<const uint128_t> x);

// inplace parallel ccrhash for many blocks
void ParaCcrHashInplace_128(absl::Span<uint128_t> inout);

// TODO(@shanzhu) Tweakable Correlation Robust Hash function (Multiple Blocks)
// See https://eprint.iacr.org/2019/074.pdf Sec 7.4

}  // namespace yacl::crypto
