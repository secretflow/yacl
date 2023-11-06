// Copyright 2019 Ant Group Co., Ltd.
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

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <limits>
#include <string>
#include <type_traits>

#include "absl/strings/numbers.h"

namespace yacl::io {

#define YACL_UNLIKELY(x) __builtin_expect((x), 0)

template <class S>
S FloatNormalization(S v) {
  // see: misra 6-2-2
  if (YACL_UNLIKELY(std::fabs(v) <= std::numeric_limits<S>::epsilon())) {
    return 0;
  }
  return v;
}

template <class S>
std::string FloatToString(S v, int precision) {
  static_assert(std::is_floating_point_v<S>);
  constexpr size_t max_len = std::numeric_limits<S>::max_digits10 + 10;
  std::string ret(max_len, '\0');
  v = FloatNormalization(v);
  auto n = std::snprintf(
      ret.data(), max_len, "%.*g",
      std::min(std::numeric_limits<S>::max_digits10, precision), v);
  ret.resize(n);
  return ret;
}

template <class S>
[[nodiscard]] bool FloatFromString(absl::string_view str, S* ret) {
  static_assert(std::is_floating_point_v<S>);
  double double_value = 0;
  if (YACL_UNLIKELY(!absl::SimpleAtod(str, &double_value))) {
    return false;
  }
  if (YACL_UNLIKELY(std::isnan(double_value))) {
    return false;
  }
  *ret = FloatNormalization(static_cast<S>(double_value));
  return true;
}

#undef YACL_UNLIKELY

}  // namespace yacl::io
