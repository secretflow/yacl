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

#include <array>
#include <vector>

#include "yacl/base/dynamic_bitset.h"
#include "yacl/base/int128.h"

namespace yacl::crypto {

constexpr size_t log2_floor(size_t x) {
  return (8 * sizeof(uint64_t) - absl::countl_zero(x)) - 1;
}

constexpr size_t log2_ceil(size_t x) { return log2_floor(x - 1) + 1; }

struct OtRecvStore {
  // Receiver choices.
  dynamic_bitset<uint128_t> choices;
  // Received blocks.
  // Choose uint128_t as block so that it can be perfectly used as AES-PRG seed.
  std::vector<uint128_t> blocks;
};

struct OtSendStore {
  // Sender received blocks.
  // Choose uint128_t as block so that it can be perfectly used as AES-PRG seed.
  std::vector<std::array<uint128_t, 2>> blocks;
};

struct BaseOtStore {
  OtSendStore send;
  OtRecvStore recv;
};

}  // namespace yacl::crypto
