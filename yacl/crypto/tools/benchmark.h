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

#pragma once

#include <memory>
#include <vector>

#include "benchmark/benchmark.h"

#include "yacl/crypto/rand/rand.h"
#include "yacl/crypto/tools/crhash.h"
#include "yacl/crypto/tools/prg.h"
#include "yacl/crypto/tools/ro.h"
#include "yacl/crypto/tools/rp.h"

namespace yacl::crypto {

class ToolBench : public benchmark::Fixture {};

// 1st arg = prg type
BENCHMARK_DEFINE_F(ToolBench, PRG)(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    Prg<int> prg(0, static_cast<PRG_MODE>(state.range(0)));

    state.ResumeTiming();
    prg();
  }
}

// 1st arg = numer of interations
BENCHMARK_DEFINE_F(ToolBench, RO)(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    auto input = RandBytes(16);

    state.ResumeTiming();
    const auto& RO = RandomOracle::GetDefault();
    for (size_t i = 0; i < n; ++i) {
      RO.Gen(input);
    }
  }
}

// 1st arg = numer of batched inputs
BENCHMARK_DEFINE_F(ToolBench, RP)(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    std::vector<uint128_t> input(n);
    std::fill(input.begin(), input.end(), 0);
    state.ResumeTiming();
    using Ctype = SymmetricCrypto::CryptoType;
    const auto& rp = RP(Ctype::AES128_CTR, 0x12345678);
    rp.Gen(absl::MakeSpan(input));
  }
}

// 1st arg = numer of batched inputs
BENCHMARK_DEFINE_F(ToolBench, CRHASH)(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    std::vector<uint128_t> input(n);
    std::fill(input.begin(), input.end(), 0);
    state.ResumeTiming();
    ParaCrHash_128(absl::MakeSpan(input));
  }
}

BENCHMARK_DEFINE_F(ToolBench, CRHASH_INPLACE)(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    std::vector<uint128_t> input(n);
    std::fill(input.begin(), input.end(), 0);
    state.ResumeTiming();
    ParaCrHashInplace_128(absl::MakeSpan(input));
  }
}

// 1st arg = numer of batched inputs
BENCHMARK_DEFINE_F(ToolBench, CCRHASH)(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    std::vector<uint128_t> input(n);
    std::fill(input.begin(), input.end(), 0);
    state.ResumeTiming();
    ParaCcrHash_128(absl::MakeSpan(input));
  }
}

BENCHMARK_DEFINE_F(ToolBench, CCRHASH_INPLACE)(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    std::vector<uint128_t> input(n);
    std::fill(input.begin(), input.end(), 0);
    state.ResumeTiming();
    ParaCcrHashInplace_128(absl::MakeSpan(input));
  }
}

}  // namespace yacl::crypto
