// Copyright 2024 Ant Group Co., Ltd.
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

class MPIntModBM : public benchmark::Fixture {
 public:
  void SetUp(::benchmark::State &state) override {
    int64_t bit_size = state.range(0);
    MPInt::RandPrimeOver(bit_size, &mod_, PrimeType::Normal);
  }

 protected:
  MPInt mod_;
};

BENCHMARK_DEFINE_F(MPIntModBM, AddMod)(benchmark::State &state) {
  for (auto _ : state) {
    state.PauseTiming();
    MPInt a, b;
    MPInt::RandomLtN(mod_, &a);
    MPInt::RandomLtN(mod_, &b);
    state.ResumeTiming();
    benchmark::DoNotOptimize(a.AddMod(b, mod_));
  }
}

BENCHMARK_DEFINE_F(MPIntModBM, MulMod)(benchmark::State &state) {
  for (auto _ : state) {
    state.PauseTiming();
    MPInt a, b;
    MPInt::RandomLtN(mod_, &a);
    MPInt::RandomLtN(mod_, &b);
    state.ResumeTiming();
    benchmark::DoNotOptimize(a.MulMod(b, mod_));
  }
}

BENCHMARK_DEFINE_F(MPIntModBM, InvMod)(benchmark::State &state) {
  for (auto _ : state) {
    state.PauseTiming();
    MPInt a;
    MPInt::RandomLtN(mod_, &a);
    state.ResumeTiming();
    benchmark::DoNotOptimize(a.InvertMod(mod_));
  }
}

BENCHMARK_DEFINE_F(MPIntModBM, PowMod)(benchmark::State &state) {
  for (auto _ : state) {
    state.PauseTiming();
    MPInt a, b;
    MPInt::RandomLtN(mod_, &a);
    MPInt::RandomLtN(mod_, &b);
    state.ResumeTiming();
    benchmark::DoNotOptimize(a.PowMod(b, mod_));
  }
}

BENCHMARK_REGISTER_F(MPIntModBM, AddMod)->RangeMultiplier(2)->Range(128, 2048);
BENCHMARK_REGISTER_F(MPIntModBM, MulMod)->RangeMultiplier(2)->Range(128, 2048);
BENCHMARK_REGISTER_F(MPIntModBM, InvMod)->RangeMultiplier(2)->Range(128, 2048);
BENCHMARK_REGISTER_F(MPIntModBM, PowMod)->RangeMultiplier(2)->Range(128, 2048);

}  // namespace yacl::math::bench
