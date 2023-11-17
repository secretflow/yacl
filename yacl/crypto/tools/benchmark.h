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

#include <memory>
#include <vector>

#include "benchmark/benchmark.h"

#include "yacl/base/aligned_vector.h"
#include "yacl/crypto/tools/expand_accumulate_code.h"
#include "yacl/crypto/tools/linear_code.h"
#include "yacl/crypto/tools/prg.h"
#include "yacl/crypto/tools/random_oracle.h"
#include "yacl/crypto/tools/random_permutation.h"
#include "yacl/crypto/tools/silver_code.h"
#include "yacl/crypto/utils/rand.h"

namespace yacl::crypto {

class ToolBench : public benchmark::Fixture {};

// 1st arg = n (generor matrix)
// 2nd arg = k (generor matrix)
BENCHMARK_DEFINE_F(ToolBench, LLC)(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    {
      auto n = state.range(0);
      auto k = state.range(1);
      uint128_t seed = RandSeed();
      LocalLinearCode<10> llc(seed, n, k);
      auto input = RandVec<uint128_t>(k);
      std::vector<uint128_t> out(n);

      state.ResumeTiming();

      llc.Encode(input, absl::MakeSpan(out));

      state.PauseTiming();
    }
    state.ResumeTiming();
  }
}

// 1st arg = n (output size)
#define DELCARE_SLV_INPLACE_BENCH(weight)                \
  BENCHMARK_DEFINE_F(ToolBench, Silver##weight##Inplace) \
  (benchmark::State & state) {                           \
    for (auto _ : state) {                               \
      state.PauseTiming();                               \
      {                                                  \
        auto n = state.range(0);                         \
        SilverCode slv(n, weight);                       \
        auto input = RandVec<uint128_t>(n * 2);          \
        state.ResumeTiming();                            \
        slv.DualEncodeInplace(absl::MakeSpan(input));    \
        state.PauseTiming();                             \
      }                                                  \
      state.ResumeTiming();                              \
    }                                                    \
  }

// 1st arg = n (output size)
#define DELCARE_SLV_BENCH(weight)                                           \
  BENCHMARK_DEFINE_F(ToolBench, Silver##weight)(benchmark::State & state) { \
    for (auto _ : state) {                                                  \
      state.PauseTiming();                                                  \
      {                                                                     \
        auto n = state.range(0);                                            \
        SilverCode slv(n, weight);                                          \
        auto input = RandVec<uint128_t>(n * 2);                             \
        auto output = std::vector<uint128_t>(n);                            \
        state.ResumeTiming();                                               \
        slv.DualEncode(absl::MakeSpan(input), absl::MakeSpan(output));      \
        state.PauseTiming();                                                \
      }                                                                     \
      state.ResumeTiming();                                                 \
    }                                                                       \
  }

DELCARE_SLV_BENCH(5);
DELCARE_SLV_INPLACE_BENCH(5);
DELCARE_SLV_BENCH(11);
DELCARE_SLV_INPLACE_BENCH(11);

// 1st arg = n (output size)
#define DELCARE_EXACC_BENCH(weight)                                        \
  BENCHMARK_DEFINE_F(ToolBench, ExAcc##weight)(benchmark::State & state) { \
    for (auto _ : state) {                                                 \
      state.PauseTiming();                                                 \
      {                                                                    \
        auto n = state.range(0);                                           \
        ExAccCode<weight> acc(n);                                          \
        auto input = RandVec<uint128_t>(n * 2);                            \
        auto output = std::vector<uint128_t>(n);                           \
        state.ResumeTiming();                                              \
        acc.DualEncode(absl::MakeSpan(input), absl::MakeSpan(output));     \
        state.PauseTiming();                                               \
      }                                                                    \
      state.ResumeTiming();                                                \
    }                                                                      \
  }

DELCARE_EXACC_BENCH(7);
DELCARE_EXACC_BENCH(11);
DELCARE_EXACC_BENCH(21);
DELCARE_EXACC_BENCH(40);

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
    const auto& RP = RandomPerm(Ctype::AES128_CTR, 0x12345678);
    RP.Gen(absl::MakeSpan(input));
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

}  // namespace yacl::crypto
