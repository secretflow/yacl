// Copyright 2024 Ant Group Co., Ltd.
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
#include <chrono>

#include "yacl/base/byte_container_view.h"
#include "yacl/base/int128.h"

using std::chrono::high_resolution_clock;
using std::chrono::time_point;

// get the Least Significant Bit of uint128_t
inline bool getLSB(const uint128_t& x) { return (x & 1) == 1; }

inline uint128_t ReverseBytes(uint128_t x) {
  auto byte_view = yacl::ByteContainerView(&x, sizeof(x));
  uint128_t ret = 0;
  auto buf = std::vector<uint8_t>(sizeof(ret));
  for (size_t i = 0; i < byte_view.size(); ++i) {
    buf[byte_view.size() - i - 1] = byte_view[i];
  }
  std::memcpy(&ret, buf.data(), buf.size());
  return ret;
}

inline time_point<high_resolution_clock> clock_start() {
  return high_resolution_clock::now();
}

inline double time_from(const time_point<high_resolution_clock>& s) {
  return std::chrono::duration_cast<std::chrono::microseconds>(
             high_resolution_clock::now() - s)
      .count();
}