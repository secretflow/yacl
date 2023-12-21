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

#include "yacl/math/galois_field/gf_configs.h"
#include "yacl/math/galois_field/gf_spi.h"
#include "yacl/math/mpint/mp_int.h"

using yacl::math::MPInt;

// state.range(0): bits of number
static void BM_MPIntAddMod(benchmark::State& state) {
  MPInt m1, m2, mod;
  MPInt::RandomExactBits(state.range(0), &m1);
  MPInt::RandomExactBits(state.range(0), &m2);
  MPInt::RandomExactBits(state.range(0) - 1, &mod);
  for (auto _ : state) {
    benchmark::DoNotOptimize(m1.AddMod(m2, mod));
  }
}

// state.range(0): bits of number
static void BM_MpfAdd(benchmark::State& state) {
  MPInt m1, m2, mod;
  MPInt::RandomExactBits(state.range(0), &m1);
  MPInt::RandomExactBits(state.range(0), &m2);
  MPInt::RandomExactBits(state.range(0) - 1, &mod);

  auto spi = yacl::math::GaloisFieldFactory::Instance().Create(
      yacl::math::kPrimeField, yacl::ArgLib = yacl::math::kMPIntLib,
      yacl::math::ArgMod = mod);

  for (auto _ : state) {
    benchmark::DoNotOptimize(spi->Add(m1, m2));
  }
}

BENCHMARK(BM_MPIntAddMod)->Arg(64)->Arg(1024)->Arg(2048)->Arg(4096);
BENCHMARK(BM_MpfAdd)->Arg(64)->Arg(1024)->Arg(2048)->Arg(4096);

int main() {
  benchmark::RunSpecifiedBenchmarks();
  return 0;
}
