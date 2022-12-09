
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

#include <iostream>
#include <random>

#include "benchmark/benchmark.h"

#include "yacl/crypto/utils/rand.h"

namespace yacl::crypto {

static void BM_RandU64InSecure(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    state.ResumeTiming();
    for (size_t i = 0; i < n; i++) {
      RandU64(false);
    }
  }
}

static void BM_RandU64Secure(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    state.ResumeTiming();
    for (size_t i = 0; i < n; i++) {
      RandU64(true);
    }
  }
}

static void BM_RandU128InSecure(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    state.ResumeTiming();
    for (size_t i = 0; i < n; i++) {
      RandU128(false);
    }
  }
}

static void BM_RandU128Secure(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    state.ResumeTiming();
    for (size_t i = 0; i < n; i++) {
      RandU128(true);
    }
  }
}

static void BM_RandBytesInSecure(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    state.ResumeTiming();
    RandBytes(n, false);
  }
}

static void BM_RandBytesSecure(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    state.ResumeTiming();
    RandBytes(n, true);
  }
}

static void BM_RandBitsInSecure(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    state.ResumeTiming();
    RandBits(n, false);
  }
}

static void BM_RandBitsSecure(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    state.ResumeTiming();
    RandBits(n, true);
  }
}

BENCHMARK(BM_RandU64InSecure)->Unit(benchmark::kMillisecond)->Arg(1 << 15);
BENCHMARK(BM_RandU64Secure)->Unit(benchmark::kMillisecond)->Arg(1 << 15);
BENCHMARK(BM_RandU128InSecure)->Unit(benchmark::kMillisecond)->Arg(1 << 15);
BENCHMARK(BM_RandU128Secure)->Unit(benchmark::kMillisecond)->Arg(1 << 15);
BENCHMARK(BM_RandBytesInSecure)->Unit(benchmark::kMillisecond)->Arg(1 << 15);
BENCHMARK(BM_RandBytesSecure)->Unit(benchmark::kMillisecond)->Arg(1 << 15);
BENCHMARK(BM_RandBitsInSecure)->Unit(benchmark::kMillisecond)->Arg(1 << 15);
BENCHMARK(BM_RandBitsSecure)->Unit(benchmark::kMillisecond)->Arg(1 << 15);

BENCHMARK_MAIN();
}  // namespace yacl::crypto
