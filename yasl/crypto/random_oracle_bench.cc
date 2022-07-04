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

#include "yasl/crypto/random_oracle.h"

static void BM_RoAesEcb(benchmark::State& state) {
  yasl::RandomOracle ro(yasl::SymmetricCrypto::CryptoType::AES128_ECB, 9527);
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);

    state.ResumeTiming();
    for (size_t i = 0; i < n; i++) {
      ro.Gen(1234);
    }
  }
}

static void BM_RoAesCbc(benchmark::State& state) {
  yasl::RandomOracle ro(yasl::SymmetricCrypto::CryptoType::AES128_CBC, 9527);
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);

    state.ResumeTiming();
    for (size_t i = 0; i < n; i++) {
      ro.Gen(1234);
    }
  }
}

BENCHMARK(BM_RoAesEcb)
    ->Unit(benchmark::kMillisecond)
    ->Arg(1024)
    ->Arg(5120)
    ->Arg(10240)
    ->Arg(20480)
    ->Arg(40960)
    ->Arg(81920)
    ->Arg(1 << 21);

BENCHMARK(BM_RoAesCbc)
    ->Unit(benchmark::kMillisecond)
    ->Arg(1024)
    ->Arg(5120)
    ->Arg(10240)
    ->Arg(20480)
    ->Arg(40960)
    ->Arg(81920)
    ->Arg(1 << 21);

BENCHMARK_MAIN();
