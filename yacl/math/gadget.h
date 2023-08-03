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

namespace yacl::math {

constexpr uint64_t Log2Floor(uint64_t x) {
  return (8 * sizeof(uint64_t) - absl::countl_zero(x)) - 1;
}

constexpr uint64_t Log2Ceil(uint64_t x) { return Log2Floor(x - 1) + 1; }

}  // namespace yacl::math
