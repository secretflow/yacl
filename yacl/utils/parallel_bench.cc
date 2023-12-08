// Copyright 2023 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "benchmark/benchmark.h"
#include "omp.h"

#include "yacl/utils/parallel.h"

namespace yacl::bench {

constexpr int64_t kTestSize = 100000;

static void BM_OpenMp(benchmark::State& state) {
  [[maybe_unused]] int64_t sum = 0;
  for (auto _ : state) {
#pragma omp parallel for
    for (int64_t i = 0; i < kTestSize; ++i) {
      sum ^= i;
    }
  }
}
BENCHMARK(BM_OpenMp);

static void BM_BatchFor(benchmark::State& state) {
  [[maybe_unused]] int64_t sum = 0;
  for (auto _ : state) {
    parallel_for(1, kTestSize, state.range(0), [&](int64_t beg, int64_t end) {
      for (int64_t i = beg; i < end; ++i) {
        sum ^= i;
      }
    });
  }
}
BENCHMARK(BM_BatchFor)
    ->Arg(1)
    ->Arg(10)
    ->Arg(100)
    ->Arg(kTestSize / omp_get_max_threads())
    ->Arg(kTestSize / omp_get_max_threads() + 1);

static void BM_AutoBatchSizeFor(benchmark::State& state) {
  [[maybe_unused]] int64_t sum = 0;
  for (auto _ : state) {
    parallel_for(1, kTestSize, [&](int64_t beg, int64_t end) {
      for (int64_t i = beg; i < end; ++i) {
        sum ^= i;
      }
    });
  }
}
BENCHMARK(BM_AutoBatchSizeFor);

}  // namespace yacl::bench

int main(int argc, char** argv) {
  ::benchmark::Initialize(&argc, argv);
  if (::benchmark::ReportUnrecognizedArguments(argc, argv)) {
    return 1;
  }

  ::benchmark::RunSpecifiedBenchmarks();
  ::benchmark::Shutdown();
  return 0;
}
