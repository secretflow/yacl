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

#include "yacl/crypto/tools/prg.h"

namespace yacl {

// Create vector<bool> random choices.
inline std::vector<bool> CreateRandomChoices(size_t len) {
  std::random_device rd;
  Prg<unsigned> prg(rd());
  const unsigned stride = sizeof(unsigned) * 8;
  std::vector<bool> ret(len, false);
  for (size_t i = 0; i < len; i += stride) {
    unsigned rand = prg();
    unsigned size = std::min(stride, static_cast<unsigned>(len - i));
    for (unsigned j = 0; j < size; ++j) {
      ret[i + j] = (rand & (1 << j)) ? true : false;
    }
  }
  return ret;
}

// CreateRandomChoiceBits
//
// Each bit of the output `vector<T>` will be a random choice bit.
// The output is `sizeof(T)` bytes aligned.
// This version is more firendly when we we are doing bit-wise message. That is
// what GMW circuits wanted.
template <typename T, std::enable_if_t<std::is_scalar<T>::value, int> = 0>
inline std::vector<T> CreateRandomChoiceBits(size_t num) {
  std::random_device rd;
  Prg<T> prg(rd());
  // Align to sizeof(T).
  constexpr int kNumBits = sizeof(T) * 8;
  std::vector<T> ret((num + kNumBits - 1) / kNumBits);
  std::generate(ret.begin(), ret.end(), [&] { return prg(); });
  return ret;
}

}  // namespace yacl
