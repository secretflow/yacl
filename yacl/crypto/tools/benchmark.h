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

class TheoreticalToolBench : public benchmark::Fixture {};
class PrgBench : public benchmark::Fixture {};
class FillPRandBench : public benchmark::Fixture {};

// 1st arg = number of batched inputs
BENCHMARK_DEFINE_F(TheoreticalToolBench, RO)(benchmark::State& state) {
  std::vector<uint128_t> input;
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    input.resize(n);
    FillRand((char*)input.data(), input.size() * sizeof(uint128_t), true);
    const auto& RO = RandomOracle::GetDefault();

    state.ResumeTiming();
    for (size_t i = 0; i < n; ++i) {
      RO.Gen({&input[i], sizeof(uint128_t)});
    }
  }
}

// 1st arg = number of batched inputs
BENCHMARK_DEFINE_F(TheoreticalToolBench, RP)(benchmark::State& state) {
  std::vector<uint128_t> input;
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    input.resize(n);
    std::fill(input.begin(), input.end(), 0);
    using Ctype = SymmetricCrypto::CryptoType;
    const auto& rp = RP(Ctype::AES128_CTR, 0x12345678);

    state.ResumeTiming();
    rp.GenForMultiInputs(absl::MakeSpan(input));
  }
}

// 1st arg = number of batched inputs
BENCHMARK_DEFINE_F(TheoreticalToolBench, CRHASH)(benchmark::State& state) {
  std::vector<uint128_t> input;
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    input.resize(n);
    std::fill(input.begin(), input.end(), 0);

    state.ResumeTiming();
    ParaCrHash_128(absl::MakeSpan(input));
  }
}

BENCHMARK_DEFINE_F(TheoreticalToolBench, CRHASH_INPLACE)
(benchmark::State& state) {
  std::vector<uint128_t> input;
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    input.resize(n);
    std::fill(input.begin(), input.end(), 0);

    state.ResumeTiming();
    ParaCrHashInplace_128(absl::MakeSpan(input));
  }
}

// 1st arg = number of batched inputs
BENCHMARK_DEFINE_F(TheoreticalToolBench, CCRHASH)(benchmark::State& state) {
  std::vector<uint128_t> input;
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    input.resize(n);
    std::fill(input.begin(), input.end(), 0);

    state.ResumeTiming();
    ParaCcrHash_128(absl::MakeSpan(input));
  }
}

// 1st arg = number of batched inputs
BENCHMARK_DEFINE_F(TheoreticalToolBench, CCRHASH_INPLACE)
(benchmark::State& state) {
  std::vector<uint128_t> input;
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    input.resize(n);
    std::fill(input.begin(), input.end(), 0);

    state.ResumeTiming();
    ParaCcrHashInplace_128(absl::MakeSpan(input));
  }
}

// 1st arg = number of desired outputs
BENCHMARK_DEFINE_F(PrgBench, PrgAesEcb)
(benchmark::State& state) {
  std::vector<uint128_t> out;
  for (auto _ : state) {
    state.PauseTiming();
    Prg<uint128_t> prg(0, PRG_MODE::kAesEcb);
    size_t n = state.range(0);
    out.resize(n);

    state.ResumeTiming();
    prg.Fill(absl::MakeSpan(out));
  }
}

// 1st arg = number of desired outputs
BENCHMARK_DEFINE_F(PrgBench, PrgSm4Ecb)
(benchmark::State& state) {
  std::vector<uint128_t> out;
  for (auto _ : state) {
    state.PauseTiming();
    Prg<uint128_t> prg(0, PRG_MODE::kSm4Ecb);
    size_t n = state.range(0);
    out.resize(n);

    state.ResumeTiming();
    prg.Fill(absl::MakeSpan(out));
  }
}

BENCHMARK_DEFINE_F(FillPRandBench, FillPRand_AES128_ECB)
(benchmark::State& state) {
  std::vector<uint128_t> out;
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    auto seed = FastRandSeed();
    auto iv = 0;
    auto count = 0;
    auto ctype = SymmetricCrypto::CryptoType::AES128_ECB;
    out.resize(n);

    state.ResumeTiming();
    FillPRand(ctype, seed, iv, count, absl::MakeSpan(out));
  }
}

BENCHMARK_DEFINE_F(FillPRandBench, FillPRandWithMersennePrime_AES128_ECB)
(benchmark::State& state) {
  std::vector<uint128_t> out;
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    auto seed = FastRandSeed();
    auto iv = 0;
    auto count = 0;
    auto ctype = SymmetricCrypto::CryptoType::AES128_ECB;
    out.resize(n);

    state.ResumeTiming();
    FillPRandWithMersennePrime(ctype, seed, iv, count, absl::MakeSpan(out));
  }
}

}  // namespace yacl::crypto
