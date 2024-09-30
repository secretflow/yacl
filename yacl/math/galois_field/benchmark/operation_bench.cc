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

#include "yacl/math/galois_field/gf.h"

namespace yacl::math::bench {

const std::array kLibraryName = {kMPIntLib};

class GaloisFieldBM : public benchmark::Fixture {
 public:
  void SetUp(::benchmark::State &state) override {
    const std::string &lib_name = kLibraryName.at(state.range(0));
    int64_t bit_size = state.range(1);
    MPInt order;
    MPInt::RandPrimeOver(bit_size, &order, PrimeType::Normal);

    gf_ = GaloisFieldFactory::Instance().Create(kPrimeField, ArgLib = lib_name,
                                                ArgMod = order);
  }

 protected:
  std::unique_ptr<GaloisField> gf_;
};

BENCHMARK_DEFINE_F(GaloisFieldBM, Add)(benchmark::State &state) {
  for (auto _ : state) {
    state.PauseTiming();
    auto a = gf_->Random();
    auto b = gf_->Random();
    state.ResumeTiming();
    benchmark::DoNotOptimize(gf_->Add(a, b));
  }
}

BENCHMARK_DEFINE_F(GaloisFieldBM, Mul)(benchmark::State &state) {
  for (auto _ : state) {
    state.PauseTiming();
    auto a = gf_->Random();
    auto b = gf_->Random();
    state.ResumeTiming();
    benchmark::DoNotOptimize(gf_->Mul(a, b));
  }
}

BENCHMARK_DEFINE_F(GaloisFieldBM, Inv)(benchmark::State &state) {
  for (auto _ : state) {
    state.PauseTiming();
    auto a = gf_->Random();
    state.ResumeTiming();
    benchmark::DoNotOptimize(gf_->Inv(a));
  }
}

BENCHMARK_DEFINE_F(GaloisFieldBM, Pow)(benchmark::State &state) {
  for (auto _ : state) {
    state.PauseTiming();
    auto a = gf_->Random();
    MPInt b;
    MPInt::RandomLtN(gf_->GetOrder(), &b);
    state.ResumeTiming();
    benchmark::DoNotOptimize(gf_->Pow(a, b));
  }
}

BENCHMARK_REGISTER_F(GaloisFieldBM, Add)
    ->ArgsProduct({{0}, benchmark::CreateRange(128, 2048, 2)});
BENCHMARK_REGISTER_F(GaloisFieldBM, Mul)
    ->ArgsProduct({{0}, benchmark::CreateRange(128, 2048, 2)});
BENCHMARK_REGISTER_F(GaloisFieldBM, Inv)
    ->ArgsProduct({{0}, benchmark::CreateRange(128, 2048, 2)});
BENCHMARK_REGISTER_F(GaloisFieldBM, Pow)
    ->ArgsProduct({{0}, benchmark::CreateRange(128, 2048, 2)});

}  // namespace yacl::math::bench
