#ifdef YASL_ENABLE_BMI2
#include <immintrin.h>
#endif

#include <random>

#include "benchmark/benchmark.h"

#include "yasl/base/int128.h"

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

#ifdef YASL_ENABLE_BMI2
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

#ifdef YASL_ENABLE_BMI2
BENCHMARK(BM_BMI2_Mul6464_128);
#endif

BENCHMARK(BM_Mul6464_128);

BENCHMARK_MAIN();