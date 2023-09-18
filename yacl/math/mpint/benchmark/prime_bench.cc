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

#include "yacl/math/mpint/mp_int.h"

namespace yacl::math::bench {

static void BM_NormalPrime(benchmark::State& state) {
  MPInt res;
  for (auto _ : state) {
    MPInt::RandPrimeOver(state.range(), &res, PrimeType::Normal);
  }
}

static void BM_BBSPrime(benchmark::State& state) {
  MPInt res;
  for (auto _ : state) {
    MPInt::RandPrimeOver(state.range(), &res, PrimeType::BBS);
  }
}

static void BM_FastSafePrime(benchmark::State& state) {
  MPInt res;
  for (auto _ : state) {
    MPInt::RandPrimeOver(state.range(), &res, PrimeType::FastSafe);
  }
}

BENCHMARK(BM_NormalPrime)
    ->Unit(benchmark::kMillisecond)
    ->DenseRange(512, 2048, 512);
BENCHMARK(BM_BBSPrime)
    ->Unit(benchmark::kMillisecond)
    ->DenseRange(512, 2048, 512);
BENCHMARK(BM_FastSafePrime)
    ->Unit(benchmark::kMillisecond)
    ->DenseRange(512, 1536, 512);

}  // namespace yacl::math::bench
