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

#include "yacl/base/block.h"
#include "yacl/crypto/tools/prg.h"
#include "yacl/utils/matrix_utils.h"

namespace {
std::vector<uint128_t> GenerateRandomUint128(size_t n) {
  std::random_device rd;
  std::seed_seq seed({rd(), rd(), rd(), rd(), rd(), rd(), rd(), rd()});
  std::mt19937 random = std::mt19937(seed);

  std::vector<uint128_t> rand_vec(n + 1);

  for (size_t i = 0; i < n; i++) {
    rand_vec[i] = yacl::MakeUint128(random(), random());
  }
  return rand_vec;
}

std::vector<yacl::block> GenerateRandomBlock(size_t n) {
  std::random_device rd;
  std::seed_seq seed({rd(), rd(), rd(), rd(), rd(), rd(), rd(), rd()});
  std::mt19937 random = std::mt19937(seed);

  std::vector<yacl::block> rand_vec(n + 1);
  for (size_t i = 0; i < n; i++) {
    rand_vec[i] = yacl::block(yacl::MakeUint128(random(), random()));
  }
  return rand_vec;
}
}  // namespace

static void BM_BlockMoveMaskEpi8(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    std::vector<yacl::block> a = GenerateRandomBlock(n);
    std::vector<int> c(n);

    state.ResumeTiming();
    for (size_t i = 0; i < n; i++) {
      c[i] = a[i].movemask_epi8();
    }
  }
}

static void BM_Uint128MoveMaskEpi8(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);

    std::vector<uint128_t> a = GenerateRandomUint128(n);
    std::vector<int> c(n);

    state.ResumeTiming();
    for (size_t i = 0; i < n; i++) {
      benchmark::DoNotOptimize(c[i] = yacl::block(a[i]).movemask_epi8());
    }
  }
}

static void BM_BlockAdd(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    std::vector<yacl::block> a = GenerateRandomBlock(n);
    std::vector<yacl::block> b = GenerateRandomBlock(n);
    std::vector<yacl::block> c(n);

    state.ResumeTiming();
    for (size_t i = 0; i < n; i++) {
      benchmark::DoNotOptimize(c[i] = a[i] + b[i]);
    }
  }
}

static void BM_Uint128Add(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);

    std::vector<uint128_t> a = GenerateRandomUint128(n);
    std::vector<uint128_t> b = GenerateRandomUint128(n);
    std::vector<uint128_t> c(n);

    state.ResumeTiming();
    for (size_t i = 0; i < n; i++) {
      benchmark::DoNotOptimize(c[i] = a[i] + b[i]);
    }
  }
}

static void BM_BlockXor(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    size_t batch_size = std::sqrt(n);
    std::vector<yacl::block> a = GenerateRandomBlock(batch_size);
    std::vector<yacl::block> b = GenerateRandomBlock(batch_size);

    size_t batch_num = (n + batch_size - 1) / batch_size;

    state.ResumeTiming();
    for (size_t i = 0; i < batch_num; i++) {
      size_t current_batch_size = std::min(n - i * batch_size, batch_size);
      for (size_t j = 0; j < current_batch_size; j++) {
        benchmark::DoNotOptimize(a[j] ^ b[j]);
      }
    }
  }
}

static void BM_Uint128Xor(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    size_t batch_size = std::sqrt(n);

    std::vector<uint128_t> a = GenerateRandomUint128(batch_size);
    std::vector<uint128_t> b = GenerateRandomUint128(batch_size);

    size_t batch_num = (n + batch_size - 1) / batch_size;

    state.ResumeTiming();
    for (size_t i = 0; i < batch_num; i++) {
      size_t current_batch_size = std::min(n - i * batch_size, batch_size);
      for (size_t j = 0; j < current_batch_size; j++) {
        benchmark::DoNotOptimize(a[j] ^ b[j]);
      }
    }
  }
}

static void BM_BlockOr(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    std::vector<yacl::block> a = GenerateRandomBlock(n);
    std::vector<yacl::block> b = GenerateRandomBlock(n);

    state.ResumeTiming();
    for (size_t i = 0; i < n; i++) {
      benchmark::DoNotOptimize(a[i] | b[i]);
    }
  }
}

static void BM_Uint128Or(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);

    std::vector<uint128_t> a = GenerateRandomUint128(n);
    std::vector<uint128_t> b = GenerateRandomUint128(n);

    state.ResumeTiming();
    for (size_t i = 0; i < n; i++) {
      benchmark::DoNotOptimize(a[i] | b[i]);
    }
  }
}

static void BM_BlockAnd(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    std::vector<yacl::block> a = GenerateRandomBlock(n);
    std::vector<yacl::block> b = GenerateRandomBlock(n);

    state.ResumeTiming();
    for (size_t i = 0; i < n; i++) {
      benchmark::DoNotOptimize(a[i] & b[i]);
    }
  }
}

static void BM_Uint128And(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);

    std::vector<uint128_t> a = GenerateRandomUint128(n);
    std::vector<uint128_t> b = GenerateRandomUint128(n);

    state.ResumeTiming();
    for (size_t i = 0; i < n; i++) {
      benchmark::DoNotOptimize(a[i] & b[i]);
    }
  }
}

static void BM_BlockRShift(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    size_t batch_size = std::sqrt(n);
    std::vector<yacl::block> a = GenerateRandomBlock(batch_size);

    size_t batch_num = (n + batch_size - 1) / batch_size;

    state.ResumeTiming();
    for (size_t i = 0; i < batch_num; i++) {
      size_t current_batch_size = std::min(n - i * batch_size, batch_size);
      for (size_t j = 0; j < current_batch_size; j++) {
        benchmark::DoNotOptimize(a[j] >> 10);
      }
    }
  }
}

static void BM_Uint128RShift(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);

    size_t batch_size = std::sqrt(n);
    std::vector<uint128_t> a = GenerateRandomUint128(batch_size);

    size_t batch_num = (n + batch_size - 1) / batch_size;

    state.ResumeTiming();
    for (size_t i = 0; i < batch_num; i++) {
      size_t current_batch_size = std::min(n - i * batch_size, batch_size);
      for (size_t j = 0; j < current_batch_size; j++) {
        benchmark::DoNotOptimize(a[j] >> 10);
      }
    }
  }
}

static void BM_BlockLShift(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    std::vector<yacl::block> a = GenerateRandomBlock(n);

    state.ResumeTiming();
    for (size_t i = 0; i < n; i++) {
      benchmark::DoNotOptimize(a[i] << 10);
    }
  }
}

static void BM_Uint128LShift(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);

    std::vector<uint128_t> a = GenerateRandomUint128(n);
    state.ResumeTiming();
    for (size_t i = 0; i < n; i++) {
      benchmark::DoNotOptimize(a[i] << 10);
    }
  }
}

namespace {
std::vector<std::vector<yacl::block>> GenerateMatrixBlock(size_t n) {
  std::random_device rd;
  std::seed_seq seed({rd(), rd(), rd(), rd(), rd(), rd(), rd(), rd()});
  std::mt19937 random = std::mt19937(seed);

  std::vector<std::vector<yacl::block>> a(n);

  for (size_t i = 0; i < n; ++i) {
    a[i].resize(n);
    for (size_t j = 0; j < n; ++j) {
      a[i][j] = yacl::block(yacl::MakeUint128(random(), random()));
    }
  }
  return a;
}

std::vector<std::vector<uint128_t>> GenerateMatrixUint128(size_t n) {
  std::random_device rd;
  std::seed_seq seed({rd(), rd(), rd(), rd(), rd(), rd(), rd(), rd()});
  std::mt19937 random = std::mt19937(seed);

  std::vector<std::vector<uint128_t>> a(n);

  for (size_t i = 0; i < n; ++i) {
    a[i].resize(n);
    for (size_t j = 0; j < n; ++j) {
      a[i][j] = yacl::MakeUint128(random(), random());
    }
  }
  return a;
}

}  // namespace

static void BM_Uint128MatrixXor(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);

    std::vector<std::vector<uint128_t>> a, b, c(n);
    a = GenerateMatrixUint128(n);
    b = GenerateMatrixUint128(n);
    for (size_t i = 0; i < n; ++i) {
      c[i].resize(n);
    }

    state.ResumeTiming();
    for (size_t i = 0; i < n; ++i) {
      for (size_t j = 0; j < n; ++j) {
        c[i][j] = 0;
        for (size_t k = 0; k < n; ++k) {
          c[i][j] += a[i][k] ^ b[k][j];
        }
      }
    }
  }
}

static void BM_BlockMatrixXor(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);

    std::vector<std::vector<yacl::block>> a, b, c(n);
    a = GenerateMatrixBlock(n);
    b = GenerateMatrixBlock(n);
    for (size_t i = 0; i < n; ++i) {
      c[i].resize(n);
    }

    state.ResumeTiming();
    for (size_t i = 0; i < n; ++i) {
      for (size_t j = 0; j < n; ++j) {
        c[i][j] = 0;
        for (size_t k = 0; k < n; ++k) {
          c[i][j] = c[i][j] + (a[i][k] ^ b[k][j]);
        }
      }
    }
  }
}

uint64_t g_interations = 10;

BENCHMARK(BM_BlockMatrixXor)
    ->Unit(benchmark::kMillisecond)
    ->Arg(10)
    ->Arg(100)
    ->Arg(200)
    ->Arg(400)
    ->Arg(800);

BENCHMARK(BM_Uint128MatrixXor)
    ->Unit(benchmark::kMillisecond)
    ->Arg(10)
    ->Arg(100)
    ->Arg(200)
    ->Arg(400)
    ->Arg(800);

BENCHMARK(BM_BlockMoveMaskEpi8)
    ->Unit(benchmark::kMillisecond)
    ->Arg(10000)
    ->Arg(20000)
    ->Arg(40000)
    ->Arg(80000)
    ->Arg(100000);

BENCHMARK(BM_Uint128MoveMaskEpi8)
    ->Unit(benchmark::kMillisecond)
    ->Arg(10000)
    ->Arg(20000)
    ->Arg(40000)
    ->Arg(80000)
    ->Arg(100000);

BENCHMARK(BM_BlockAdd)
    //->Iterations(g_interations)
    ->Unit(benchmark::kMillisecond)
    ->Arg(1024000)
    ->Arg(2048000)
    ->Arg(4096000)
    ->Arg(8192000)
    ->Arg(16384000);

BENCHMARK(BM_Uint128Add)
    //->Iterations(g_interations)
    ->Unit(benchmark::kMillisecond)
    ->Arg(1024000)
    ->Arg(2048000)
    ->Arg(4096000)
    ->Arg(8192000)
    ->Arg(16384000);

BENCHMARK(BM_BlockXor)
    ->Unit(benchmark::kMillisecond)
    ->Iterations(g_interations)
    ->Arg(1024000)
    ->Arg(2048000)
    ->Arg(4096000)
    ->Arg(8192000)
    ->Arg(16384000);

BENCHMARK(BM_Uint128Xor)
    ->Unit(benchmark::kMillisecond)
    ->Iterations(g_interations)
    ->Arg(1024000)
    ->Arg(2048000)
    ->Arg(4096000)
    ->Arg(8192000)
    ->Arg(16384000);

BENCHMARK(BM_BlockOr)
    ->Unit(benchmark::kMillisecond)
    ->Iterations(10)
    ->Arg(1024000)
    ->Arg(2048000)
    ->Arg(4096000)
    ->Arg(8192000)
    ->Arg(16384000);

BENCHMARK(BM_Uint128Or)
    ->Unit(benchmark::kMillisecond)
    ->Iterations(g_interations)
    ->Arg(1024000)
    ->Arg(2048000)
    ->Arg(4096000)
    ->Arg(8192000)
    ->Arg(16384000);

BENCHMARK(BM_BlockAnd)
    ->Unit(benchmark::kMillisecond)
    ->Iterations(g_interations)
    ->Arg(1024000)
    ->Arg(2048000)
    ->Arg(4096000)
    ->Arg(8192000)
    ->Arg(16384000);

BENCHMARK(BM_Uint128And)
    ->Unit(benchmark::kMillisecond)
    ->Iterations(g_interations)
    ->Arg(1024000)
    ->Arg(2048000)
    ->Arg(4096000)
    ->Arg(8192000)
    ->Arg(16384000);

BENCHMARK(BM_BlockRShift)
    ->Unit(benchmark::kMillisecond)
    ->Iterations(g_interations)
    ->Arg(1024000)
    ->Arg(2048000)
    ->Arg(4096000)
    ->Arg(8192000)
    ->Arg(16384000);

BENCHMARK(BM_Uint128RShift)
    ->Unit(benchmark::kMillisecond)
    ->Iterations(g_interations)
    ->Arg(1024000)
    ->Arg(2048000)
    ->Arg(4096000)
    ->Arg(8192000)
    ->Arg(16384000);

BENCHMARK(BM_BlockLShift)
    ->Unit(benchmark::kMillisecond)
    ->Iterations(g_interations)
    ->Arg(1024000)
    ->Arg(2048000)
    ->Arg(4096000)
    ->Arg(8192000)
    ->Arg(16384000);

BENCHMARK(BM_Uint128LShift)
    ->Unit(benchmark::kMillisecond)
    ->Iterations(g_interations)
    ->Arg(1024000)
    ->Arg(2048000)
    ->Arg(4096000)
    ->Arg(8192000)
    ->Arg(16384000);
