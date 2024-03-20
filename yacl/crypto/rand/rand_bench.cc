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

#include "yacl/crypto/rand/rand.h"
#include "yacl/secparam.h"

namespace yacl::crypto {

static void BM_SecureRand(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    {
      // setup input
      size_t n = state.range(0);
      std::vector<char> out(n);
      auto& ctx = RandCtx::GetDefault();

      // benchmark
      state.ResumeTiming();
      FillRand(ctx, out.data(), out.size(), false);
      state.PauseTiming();
    }
    state.ResumeTiming();
  }
}

static void BM_FastRand(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    {
      // setup input
      size_t n = state.range(0);
      std::vector<char> out(n);
      auto& ctx = RandCtx::GetDefault();

      // benchmark
      state.ResumeTiming();
      FillRand(ctx, out.data(), out.size(), true);
      state.PauseTiming();
    }
    state.ResumeTiming();
  }
}

static void BM_IcDrbg(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    {
      // setup input
      size_t n = state.range(0);
      std::vector<char> out(n);

      auto drbg = DrbgFactory::Instance().Create("ic-hash-drbg");
      drbg->SetSeed(1234);

      // benchmark
      state.ResumeTiming();
      drbg->Fill(out.data(), out.size());
      state.PauseTiming();
    }
    state.ResumeTiming();
  }
}

BENCHMARK(BM_SecureRand)
    ->Unit(benchmark::kMillisecond)
    ->Arg(1024)
    ->Arg(5120)
    ->Arg(10240)
    ->Arg(20480)
    ->Arg(40960)
    ->Arg(81920)
    ->Arg(1 << 24);

BENCHMARK(BM_FastRand)
    ->Unit(benchmark::kMillisecond)
    ->Arg(1024)
    ->Arg(5120)
    ->Arg(10240)
    ->Arg(20480)
    ->Arg(40960)
    ->Arg(81920)
    ->Arg(1 << 24);

BENCHMARK(BM_IcDrbg)
    ->Unit(benchmark::kMillisecond)
    ->Arg(1024)
    ->Arg(5120)
    ->Arg(10240)
    ->Arg(20480)
    ->Arg(40960)
    ->Arg(81920)
    ->Arg(1 << 24);
}  // namespace yacl::crypto
