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

#ifdef YACL_ENABLE_BMI2
#include <immintrin.h>
#endif

#include <random>

#include "benchmark/benchmark.h"

#include "yacl/base/int128.h"

namespace {

constexpr size_t kSampleSize = 1ul << 20;

std::vector<std::pair<uint64_t, uint64_t>> GetRandomSamples(size_t n) {
  std::vector<std::pair<uint64_t, uint64_t>> values;
  std::random_device r;
  std::mt19937 random(r());
  std::uniform_int_distribution<uint64_t> uniform_h;
  values.reserve(n);
  for (size_t i = 0; i < n; ++i) {
    values.emplace_back(uniform_h(random), uniform_h(random));
  }
  return values;
}

/// NOTE:
/// If we open bmi2, say `-march=native`, the mul6464_128 is translated into
/// bmi2 instrunction `mulx`. Otherwise, it emits `mulq`.
void BM_Mul6464_128(benchmark::State& state) {
  auto values = GetRandomSamples(kSampleSize);
  while (state.KeepRunningBatch(values.size())) {
    for (const auto& pair : values) {
      benchmark::DoNotOptimize(uint128_t(pair.first) * pair.second);
    }
  }
}

#ifdef YACL_ENABLE_BMI2
void BM_BMI2_Mul6464_128(benchmark::State& state) {
  long long unsigned int hi;
  long long unsigned int lo;
  auto values = GetRandomSamples(kSampleSize);
  while (state.KeepRunningBatch(values.size())) {
    for (const auto& pair : values) {
      benchmark::DoNotOptimize(lo = _mulx_u64(pair.first, pair.second, &hi));
    }
  }
}
#endif

}  // namespace

#ifdef YACL_ENABLE_BMI2
BENCHMARK(BM_BMI2_Mul6464_128);
#endif

BENCHMARK(BM_Mul6464_128);
