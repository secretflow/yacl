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

#include "yacl/crypto/tools/random_permutation.h"

namespace yacl::crypto {

static void BM_RP(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    std::vector<uint128_t> input(n);
    std::fill(input.begin(), input.end(), 0);
    state.ResumeTiming();
    using Ctype = SymmetricCrypto::CryptoType;
    const auto& RP = RandomPerm(Ctype::AES128_CTR, 0x12345678);
    RP.Gen(absl::MakeSpan(input));
  }
}

static void BM_CrHash(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    std::vector<uint128_t> input(n);
    std::fill(input.begin(), input.end(), 0);
    state.ResumeTiming();
    ParaCrHash_128(absl::MakeSpan(input));
  }
}

// static void BM_CcrHash(benchmark::State& state) {
//   for (auto _ : state) {
//     state.PauseTiming();
//     size_t n = state.range(0);
//     std::vector<uint128_t> input(n);
//     std::fill(input.begin(), input.end(), 0);
//     state.ResumeTiming();
//     ParaCcrHash_128(absl::MakeSpan(input));
//   }
// }

// Register the function as a benchmark
BENCHMARK(BM_RP)
    ->Unit(benchmark::kMillisecond)
    ->Arg(1024)
    ->Arg(5120)
    ->Arg(10240)
    ->Arg(20480)
    ->Arg(40960)
    ->Arg(81920)
    ->Arg(1 << 24);

BENCHMARK(BM_CrHash)
    ->Unit(benchmark::kMillisecond)
    ->Arg(1024)
    ->Arg(5120)
    ->Arg(10240)
    ->Arg(20480)
    ->Arg(40960)
    ->Arg(81920)
    ->Arg(1 << 24);

// BENCHMARK(BM_CcrHash)
//     ->Unit(benchmark::kMillisecond)
//     ->Arg(1024)
//     ->Arg(5120)
//     ->Arg(10240)
//     ->Arg(20480)
//     ->Arg(40960)
//     ->Arg(81920)
//     ->Arg(1 << 24);

}  // namespace yacl::crypto
