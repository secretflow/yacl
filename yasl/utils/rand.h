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

#include <openssl/rand.h>

#include <random>

#include "absl/types/span.h"

#include "yasl/base/exception.h"
#include "yasl/base/int128.h"

namespace yasl {

uint64_t DrbgRandSeed();

inline uint128_t RandSeed(bool use_drbg = false) {
  uint64_t lhs, rhs;
  if (use_drbg) {
    lhs = DrbgRandSeed();
    rhs = DrbgRandSeed();
  } else {
    // call random_device four times, make sure uint128 is random in 2^128 set.
    std::random_device rd;
    lhs = static_cast<uint64_t>(rd()) << 32 | rd();
    rhs = static_cast<uint64_t>(rd()) << 32 | rd();
  }
  return yasl::MakeUint128(lhs, rhs);
}

template <typename T,
          std::enable_if_t<std::is_standard_layout<T>::value, int> = 0>
inline void RandBytes(absl::Span<T> out) {
  const size_t nbytes = out.size() * sizeof(T);

  YASL_ENFORCE(RAND_bytes(reinterpret_cast<uint8_t*>(out.data()), nbytes) == 1);
}

}  // namespace yasl
