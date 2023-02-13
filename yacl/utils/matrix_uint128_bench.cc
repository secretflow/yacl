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

#include <future>
#include <iostream>
#include <random>

#include "benchmark/benchmark.h"

#include "yacl/crypto/tools/prg.h"
#include "yacl/utils/matrix_utils.h"

using namespace std::chrono;

namespace {
/*
 * sse_* function from
 * https://github.com/osu-crypto/libOTe/blob/master/libOTe/Tools/Tools.cpp
 * libOTe License:
 *  This project has been placed in the public domain. As such, you are
 * unrestricted in how you use it, commercial or otherwise.
 */
void SseLoadSubSquare(std::array<uint128_t, 128>& in,
                      std::array<uint128_t, 2>& out, uint64_t x, uint64_t y) {
  static_assert(sizeof(std::array<std::array<uint8_t, 16>, 2>) ==
                    sizeof(std::array<uint128_t, 2>),
                "");
  static_assert(sizeof(std::array<std::array<uint8_t, 16>, 128>) ==
                    sizeof(std::array<uint128_t, 128>),
                "");

  std::array<std::array<uint8_t, 16>, 2>& outByteView =
      *(std::array<std::array<uint8_t, 16>, 2>*)&out;
  std::array<std::array<uint8_t, 16>, 128>& inByteView =
      *(std::array<std::array<uint8_t, 16>, 128>*)&in;

  for (int l = 0; l < 16; l++) {
    outByteView[0][l] = inByteView[16 * x + l][2 * y];
    outByteView[1][l] = inByteView[16 * x + l][2 * y + 1];
  }
}

// given a 16x16 sub square, place its transpose into uint16_tOutView at
// rows  16*h, ..., 16 *(h+1)  a byte  columns w, w+1.
void SseTransposeSubSquare(std::array<uint128_t, 128>& out,
                           std::array<uint128_t, 2>& in, uint64_t x,
                           uint64_t y) {
  static_assert(sizeof(std::array<std::array<uint16_t, 8>, 128>) ==
                    sizeof(std::array<uint128_t, 128>),
                "");

  std::array<std::array<uint16_t, 8>, 128>& outU16View =
      *(std::array<std::array<uint16_t, 8>, 128>*)&out;

  for (int j = 0; j < 8; j++) {
    outU16View[16 * x + 7 - j][y] = yacl::block(in[0]).movemask_epi8();
    outU16View[16 * x + 15 - j][y] = yacl::block(in[1]).movemask_epi8();

    in[0] = (in[0] << 1);
    in[1] = (in[1] << 1);
  }
}

void SseTranspose128Uint128(std::array<uint128_t, 128>* inout) {
  std::array<uint128_t, 2> a, b;

  for (int j = 0; j < 8; j++) {
    SseLoadSubSquare((*inout), a, j, j);
    SseTransposeSubSquare((*inout), a, j, j);

    for (int k = 0; k < j; k++) {
      SseLoadSubSquare((*inout), a, k, j);
      SseLoadSubSquare((*inout), b, j, k);
      SseTransposeSubSquare((*inout), a, j, k);
      SseTransposeSubSquare((*inout), b, k, j);
    }
  }
}

void GenerateRandomMatrix(std::array<uint128_t, 128>* matrix) {
  std::random_device rd;
  yacl::crypto::Prg<uint128_t> prg;
  prg.SetSeed(rd());
  for (size_t i = 0; i < 128; i++) {
    (*matrix)[i] = prg();
  }
}

}  // namespace

static void BM_SseTransUint128(benchmark::State& state) {
  std::array<uint128_t, 128> matrix;
  GenerateRandomMatrix(&matrix);
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);

    state.ResumeTiming();
    for (size_t i = 0; i < n; i++) {
      SseTranspose128Uint128(&matrix);
    }
  }
}

static void BM_SseTransBlock(benchmark::State& state) {
  std::array<uint128_t, 128> matrix;
  GenerateRandomMatrix(&matrix);
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    state.ResumeTiming();
    for (size_t i = 0; i < n; i++) {
      yacl::SseTranspose128(&matrix);
    }
  }
}

BENCHMARK(BM_SseTransUint128)
    ->Unit(benchmark::kMillisecond)
    ->Arg(1024)
    ->Arg(5120)
    ->Arg(10240)
    ->Arg(20480)
    ->Arg(40960)
    ->Arg(81920)
    ->Arg(1 << 20);

BENCHMARK(BM_SseTransBlock)
    ->Unit(benchmark::kMillisecond)
    ->Arg(1024)
    ->Arg(5120)
    ->Arg(10240)
    ->Arg(20480)
    ->Arg(40960)
    ->Arg(81920)
    ->Arg(1 << 20);
