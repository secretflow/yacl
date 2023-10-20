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
#include <cstddef>
#include <string>
#include <type_traits>

#include "yacl/base/block.h"
#include "yacl/base/byte_container_view.h"
#include "yacl/base/int128.h"

namespace yacl {

inline constexpr uint128_t GetBit(uint128_t i, size_t pos) {
  return (i >> pos) & 1;
}

// TODO(shuyan): check MP-SPDZ implementation of `EklundhTranspose128`
// TODO(shuyan): consider introduce 1024x128 SSE transpose in the future.
template <size_t N = 1>
inline void NaiveTranspose(std::array<uint128_t, 128 * N>* inout) {
  std::array<uint128_t, 128 * N> in = *inout;
  for (size_t i = 0; i < 128 * N; ++i) {
    uint128_t t = 0;
    for (size_t j = 0; j < 128; ++j) {
      t |= GetBit(in[j], i) << j;
    }
    (*inout)[i] = t;
  }
}

// matrix_transpose_benchmark
// BM_NaiveTrans/1024              67.8 ms         67.8 ms           10
// BM_NaiveTrans/5120               337 ms          337 ms            2
// BM_EklundhTrans/1024            4.11 ms         4.11 ms          170
// BM_EklundhTrans/5120            20.7 ms         20.7 ms           34
// BM_SseTrans/1024                2.01 ms         2.01 ms          349
// BM_SseTrans/5120                10.0 ms         10.0 ms           70
// BM_EklundhTrans1024/128         4.29 ms         4.29 ms          163
// BM_EklundhTrans1024/640         21.5 ms         21.5 ms           33
// BM_SseTrans1024/128             1.75 ms         1.75 ms          401
// BM_SseTrans1024/640             8.73 ms         8.73 ms           80
//
// sse internal use uint128, only __mm_movemask_epi8 use block
// BM_SseTrans/1024                5.71 ms         5.71 ms          123
// BM_SseTrans/5120                28.5 ms         28.5 ms           25
// BM_SseTrans1024/128             8.20 ms         8.20 ms           85
// BM_SseTrans1024/640             41.0 ms         41.0 ms           17

void EklundhTranspose128(std::array<uint128_t, 128>* inout);

void SseTranspose128(std::array<uint128_t, 128>* inout);

void AvxTranspose128(std::array<uint128_t, 128>* inout);

// void AvxTranspose128x1024(std::array<std::array<uint128_t, 8>, 128>* inout);

void SseTranspose128x1024(std::array<std::array<block, 8>, 128>& inout);
void SseTranspose128x1024(std::array<std::array<uint128_t, 8>, 128>* inout);

void EklundhTranspose128x1024(std::array<std::array<block, 8>, 128>& inout);
void EklundhTranspose128x1024(std::array<std::array<uint128_t, 8>, 128>* inout);

void MatrixTranspose128(std::array<uint128_t, 128>* inout);
void MatrixTranspose128x1024(std::array<std::array<block, 8>, 128>& inout);

}  // namespace yacl
