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

namespace {
void GenerateRandomMatrix(std::array<uint128_t, 128>* matrix) {
  std::random_device rd;
  yacl::crypto::Prg<uint128_t> prg;
  prg.SetSeed(rd());
  for (size_t i = 0; i < 128; i++) {
    (*matrix)[i] = prg();
  }
}

void GenerateRandomMatrix1024(
    std::array<std::array<uint128_t, 8>, 128>* matrix) {
  std::random_device rd;
  yacl::crypto::Prg<uint128_t> prg;
  prg.SetSeed(rd());
  for (size_t i = 0; i < 128; i++) {
    (*matrix)[i][0] = prg();
    (*matrix)[i][1] = prg();
    (*matrix)[i][2] = prg();
    (*matrix)[i][3] = prg();
    (*matrix)[i][4] = prg();
    (*matrix)[i][5] = prg();
    (*matrix)[i][6] = prg();
    (*matrix)[i][7] = prg();
  }
}
}  // namespace

static void BM_NaiveTrans(benchmark::State& state) {
  std::array<uint128_t, 128> matrix;
  GenerateRandomMatrix(&matrix);
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    state.ResumeTiming();
    for (size_t i = 0; i < n; i++) {
      yacl::NaiveTranspose(&matrix);
    }
  }
}

static void BM_SseTrans(benchmark::State& state) {
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

static void BM_EklundhTrans(benchmark::State& state) {
  std::array<uint128_t, 128> matrix;
  GenerateRandomMatrix(&matrix);
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    state.ResumeTiming();
    for (size_t i = 0; i < n; i++) {
      yacl::EklundhTranspose128(&matrix);
    }
  }
}

static void BM_EklundhTrans1024(benchmark::State& state) {
  std::array<std::array<uint128_t, 8>, 128> matrix;
  GenerateRandomMatrix1024(&matrix);
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    state.ResumeTiming();
    for (size_t i = 0; i < n; i++) {
      yacl::EklundhTranspose128x1024(&matrix);
    }
  }
}

static void BM_SseTrans1024(benchmark::State& state) {
  std::array<std::array<uint128_t, 8>, 128> matrix;
  GenerateRandomMatrix1024(&matrix);
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    state.ResumeTiming();
    for (size_t i = 0; i < n; i++) {
      yacl::SseTranspose128x1024(&matrix);
    }
  }
}

#ifdef YACL_ENABLE_BMI2
static void BM_AvxTrans(benchmark::State& state) {
  // AVX need to be aligned to 32 bytes.
  alignas(32) std::array<uint128_t, 128> matrix;
  GenerateRandomMatrix(&matrix);
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    state.ResumeTiming();
    for (size_t i = 0; i < n; i++) {
      yacl::AvxTranspose128(&matrix);
    }
  }
}
#endif

BENCHMARK(BM_NaiveTrans)
    ->Unit(benchmark::kMillisecond)
    ->Arg(1024)
    ->Arg(5120)
    ->Arg(10240)
    ->Arg(20480)
    ->Arg(40960)
    ->Arg(81920);

BENCHMARK(BM_EklundhTrans)
    ->Unit(benchmark::kMillisecond)
    ->Arg(1024)
    ->Arg(5120)
    ->Arg(10240)
    ->Arg(20480)
    ->Arg(40960)
    ->Arg(81920);

BENCHMARK(BM_SseTrans)
    ->Unit(benchmark::kMillisecond)
    ->Arg(1024)
    ->Arg(5120)
    ->Arg(10240)
    ->Arg(20480)
    ->Arg(40960)
    ->Arg(81920)
    ->Arg(1 << 24);

BENCHMARK(BM_EklundhTrans1024)
    ->Unit(benchmark::kMillisecond)
    ->Arg(128)
    ->Arg(640)
    ->Arg(1280)
    ->Arg(2560)
    ->Arg(5120)
    ->Arg(10240);

BENCHMARK(BM_SseTrans1024)
    ->Unit(benchmark::kMillisecond)
    ->Arg(128)
    ->Arg(640)
    ->Arg(1280)
    ->Arg(2560)
    ->Arg(5120)
    ->Arg(10240)
    ->Arg(1 << 21);

#ifdef YACL_ENABLE_BMI2
BENCHMARK(BM_AvxTrans)
    ->Unit(benchmark::kMillisecond)
    ->Arg(1024)
    ->Arg(5120)
    ->Arg(10240)
    ->Arg(20480)
    ->Arg(40960)
    ->Arg(81920)
    ->Arg(1 << 24);
#endif
