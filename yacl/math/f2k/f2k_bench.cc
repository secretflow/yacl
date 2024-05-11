// Copyright 2023 Ant Group Co., Ltd.
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

#include "benchmark/benchmark.h"

#include "yacl/crypto/rand/rand.h"
#include "yacl/math/f2k/f2k.h"

static void BM_ClMul128_block(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);

    auto x = yacl::crypto::RandVec<yacl::block>(n);
    auto y = yacl::crypto::RandVec<yacl::block>(n);

    state.ResumeTiming();
    for (size_t i = 0; i < n; i++) {
      benchmark::DoNotOptimize(yacl::ClMul128(x[i], y[i]));
    }
  }
}

static void BM_GfMul128_block(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);

    auto x = yacl::crypto::RandVec<yacl::block>(n);
    auto y = yacl::crypto::RandVec<yacl::block>(n);

    state.ResumeTiming();
    for (size_t i = 0; i < n; i++) {
      benchmark::DoNotOptimize(yacl::GfMul128(x[i], y[i]));
    }
  }
}

static void BM_ClMul128(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);

    auto x = yacl::crypto::RandVec<uint128_t>(n);
    auto y = yacl::crypto::RandVec<uint128_t>(n);

    state.ResumeTiming();
    for (size_t i = 0; i < n; i++) {
      benchmark::DoNotOptimize(yacl::ClMul128(x[i], y[i]));
    }
  }
}

static void BM_GfMul128(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);

    auto x = yacl::crypto::RandVec<uint128_t>(n);
    auto y = yacl::crypto::RandVec<uint128_t>(n);

    state.ResumeTiming();
    for (size_t i = 0; i < n; i++) {
      benchmark::DoNotOptimize(yacl::GfMul128(x[i], y[i]));
    }
  }
}

static void BM_GfMul128_inner_product(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    auto x = yacl::crypto::RandVec<uint128_t>(n);
    auto y = yacl::crypto::RandVec<uint128_t>(n);

    auto x_span = absl::MakeSpan(x);
    auto y_span = absl::MakeSpan(y);

    state.ResumeTiming();
    yacl::GfMul128(x_span, y_span);
  }
}

static void BM_ClMul64(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);

    auto x = yacl::crypto::RandVec<uint64_t>(n);
    auto y = yacl::crypto::RandVec<uint64_t>(n);

    state.ResumeTiming();
    for (size_t i = 0; i < n; i++) {
      benchmark::DoNotOptimize(yacl::ClMul64(x[i], y[i]));
    }
  }
}

static void BM_GfMul64(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);

    auto x = yacl::crypto::RandVec<uint64_t>(n);
    auto y = yacl::crypto::RandVec<uint64_t>(n);

    state.ResumeTiming();
    for (size_t i = 0; i < n; i++) {
      benchmark::DoNotOptimize(yacl::GfMul64(x[i], y[i]));
    }
  }
}

static void BM_GfMul64_inner_product(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);

    auto x = yacl::crypto::RandVec<uint64_t>(n);
    auto y = yacl::crypto::RandVec<uint64_t>(n);

    auto x_span = absl::MakeSpan(x);
    auto y_span = absl::MakeSpan(y);

    state.ResumeTiming();
    yacl::GfMul64(x_span, y_span);
  }
}

uint64_t g_interations = 10;

BENCHMARK(BM_ClMul128_block)
    ->Unit(benchmark::kMillisecond)
    ->Iterations(g_interations)
    ->Arg(1 << 20)
    ->Arg(1 << 21)
    ->Arg(1 << 22)
    ->Arg(1 << 23)
    ->Arg(1 << 24)
    ->Arg(1 << 25);

BENCHMARK(BM_GfMul128_block)
    ->Unit(benchmark::kMillisecond)
    ->Iterations(g_interations)
    ->Arg(1 << 20)
    ->Arg(1 << 21)
    ->Arg(1 << 22)
    ->Arg(1 << 23)
    ->Arg(1 << 24)
    ->Arg(1 << 25);

BENCHMARK(BM_ClMul128)
    ->Unit(benchmark::kMillisecond)
    ->Iterations(g_interations)
    ->Arg(1 << 20)
    ->Arg(1 << 21)
    ->Arg(1 << 22)
    ->Arg(1 << 23)
    ->Arg(1 << 24)
    ->Arg(1 << 25);

BENCHMARK(BM_GfMul128)
    ->Unit(benchmark::kMillisecond)
    ->Iterations(g_interations)
    ->Arg(1 << 20)
    ->Arg(1 << 21)
    ->Arg(1 << 22)
    ->Arg(1 << 23)
    ->Arg(1 << 24)
    ->Arg(1 << 25);

BENCHMARK(BM_GfMul128_inner_product)
    ->Unit(benchmark::kMillisecond)
    ->Iterations(g_interations)
    ->Arg(1 << 20)
    ->Arg(1 << 21)
    ->Arg(1 << 22)
    ->Arg(1 << 23)
    ->Arg(1 << 24)
    ->Arg(1 << 25);

BENCHMARK(BM_ClMul64)
    ->Unit(benchmark::kMillisecond)
    ->Iterations(g_interations)
    ->Arg(1 << 20)
    ->Arg(1 << 21)
    ->Arg(1 << 22)
    ->Arg(1 << 23)
    ->Arg(1 << 24)
    ->Arg(1 << 25);

BENCHMARK(BM_GfMul64)
    ->Unit(benchmark::kMillisecond)
    ->Iterations(g_interations)
    ->Arg(1 << 20)
    ->Arg(1 << 21)
    ->Arg(1 << 22)
    ->Arg(1 << 23)
    ->Arg(1 << 24)
    ->Arg(1 << 25);

BENCHMARK(BM_GfMul64_inner_product)
    ->Unit(benchmark::kMillisecond)
    ->Iterations(g_interations)
    ->Arg(1 << 20)
    ->Arg(1 << 21)
    ->Arg(1 << 22)
    ->Arg(1 << 23)
    ->Arg(1 << 24)
    ->Arg(1 << 25);
