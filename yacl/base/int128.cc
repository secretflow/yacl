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

#include "yacl/base/int128.h"

#include <utility>

// For importing ostream implementation.
#include "absl/numeric/int128.h"

namespace std {

std::ostream& operator<<(std::ostream& os, int128_t x) {
  return os << static_cast<absl::int128>(x);
}

std::ostream& operator<<(std::ostream& os, uint128_t x) {
  return os << static_cast<absl::uint128>(x);
}

}  // namespace std

namespace yacl {

std::pair<int64_t, uint64_t> DecomposeInt128(int128_t v) {
  auto absl_v = static_cast<absl::int128>(v);
  return {absl::Int128High64(absl_v), absl::Int128Low64(absl_v)};
}

std::pair<uint64_t, uint64_t> DecomposeUInt128(uint128_t v) {
  auto absl_v = static_cast<absl::uint128>(v);
  return {absl::Uint128High64(absl_v), absl::Uint128Low64(absl_v)};
}

}  // namespace yacl
