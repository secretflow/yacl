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

#include <random>

#include "yasl/base/int128.h"

namespace yasl {

inline uint128_t RandSeed() {
  // call random_device four times, make sure uint128 is random in 2^128 set.
  std::random_device rd;
  uint64_t lhs = static_cast<uint64_t>(rd()) << 32 | rd();
  uint64_t rhs = static_cast<uint64_t>(rd()) << 32 | rd();
  return yasl::MakeUint128(lhs, rhs);
}

}  // namespace yasl