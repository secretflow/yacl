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

#include <algorithm>

#include "benchmark/benchmark.h"

#include "yacl/crypto/tools/random_oracle.h"

namespace yacl {

static void BM_RO(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    std::vector<uint8_t> input(n);
    std::fill(input.begin(), input.end(), 0);
    state.ResumeTiming();
    const auto& RO = RandomOracle::GetDefault();
    RO.Gen(Buffer(input.data(), n));
  }
}

// Register the function as a benchmark
BENCHMARK(BM_RO)
    ->Unit(benchmark::kMillisecond)
    ->Arg(1024)
    ->Arg(5120)
    ->Arg(10240)
    ->Arg(20480)
    ->Arg(40960)
    ->Arg(81920)
    ->Arg(1 << 24);

// Run the benchmark
BENCHMARK_MAIN();
}  // namespace yacl
