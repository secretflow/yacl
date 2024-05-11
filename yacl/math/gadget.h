// Copyright 2023 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include "absl/strings/numbers.h"

#include "yacl/base/exception.h"

namespace yacl::math {

inline uint64_t Log2Floor(uint64_t x) {
  YACL_ENFORCE(x != 0, "log2(0) is undefined");
  return (8 * sizeof(uint64_t) - absl::countl_zero(x)) - 1;
}

inline uint64_t Log2Ceil(uint64_t x) {
  YACL_ENFORCE(x != 0, "log2(0) is undefined");
  return x == 1 ? 0 : Log2Floor(x - 1) + 1;
}

constexpr uint64_t DivCeil(uint64_t x, uint64_t y) {
  return x == 0 ? 0 : 1 + ((x - 1) / y);  // x-1 avoid overflow
}

constexpr uint64_t RoundUpTo(uint64_t x, uint64_t y) {
  return DivCeil(x, y) * y;
}

}  // namespace yacl::math
