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

#include "absl/strings/str_split.h"
#include "benchmark/benchmark.h"
#include "gflags/gflags.h"

#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/utils/spi/spi_factory.h"

namespace yacl::crypto::bench {

DEFINE_string(curve, "sm2", "Select curve to bench");
DEFINE_string(lib, "", "Select lib to bench");

class EccBencher {
 public:
  explicit EccBencher(std::unique_ptr<EcGroup> ec) : ec_(std::move(ec)) {}

  void Register() {
    std::string prefix =
        fmt::format("{}/{}", ec_->GetCurveName(), ec_->GetLibraryName());
    fmt::print("Register {}\n", prefix);

    benchmark::RegisterBenchmark(
        fmt::format("{}/BM_MulBase", prefix).c_str(),
        [this](benchmark::State& st) { BenchMulBase(st); })
        ->Arg(16)
        ->Arg(256)
        ->Arg(448);
    benchmark::RegisterBenchmark(fmt::format("{}/BM_Mul", prefix).c_str(),
                                 [this](benchmark::State& st) { BenchMul(st); })
        ->Arg(16)
        ->Arg(256)
        ->Arg(448);
    benchmark::RegisterBenchmark(
        fmt::format("{}/BM_MulDoubleBase", prefix).c_str(),
        [this](benchmark::State& st) { BenchMulDoubleBase(st); })
        ->Arg(16)
        ->Arg(256)
        ->Arg(448);

    // for small func
    benchmark::IterationCount n = 1000;
    // mcl not support hash point now
    if (absl::AsciiStrToLower(ec_->GetLibraryName()) != "libmcl") {
      benchmark::RegisterBenchmark(
          fmt::format("{}/BM_HashPoint", prefix).c_str(),
          [this](benchmark::State& st) { BenchHashPoint(st); })
          ->Iterations(n);
    } else {
      fmt::print("\t{} not supports BM_HashPoint\n", ec_->GetLibraryName());
    }
    benchmark::RegisterBenchmark(
        fmt::format("{}/BM_PointEqual", prefix).c_str(),
        [this](benchmark::State& st) { BenchPointEqual(st); })
        ->Iterations(n);
    benchmark::RegisterBenchmark(fmt::format("{}/BM_Add", prefix).c_str(),
                                 [this](benchmark::State& st) { BenchAdd(st); })
        ->Iterations(n);
  }

  void BenchMulBase(benchmark::State& state) {
    MPInt s;
    for (auto _ : state) {
      state.PauseTiming();
      MPInt::RandomMonicExactBits(state.range(), &s);
      state.ResumeTiming();

      ec_->MulBase(s);
    }
  }

  void BenchMul(benchmark::State& state) {
    MPInt p;
    MPInt s;
    for (auto _ : state) {
      state.PauseTiming();
      MPInt::RandomExactBits(256, &p);
      auto point = ec_->MulBase(p);
      MPInt::RandomMonicExactBits(state.range(), &s);
      state.ResumeTiming();

      ec_->Mul(point, s);
    }
  }

  void BenchMulDoubleBase(benchmark::State& state) {
    MPInt p;
    MPInt s1;
    MPInt s2;

    for (auto _ : state) {
      state.PauseTiming();
      MPInt::RandomExactBits(256, &p);
      auto point = ec_->MulBase(p);
      MPInt::RandomMonicExactBits(state.range(), &s1);
      MPInt::RandomMonicExactBits(state.range(), &s2);
      state.ResumeTiming();

      ec_->MulDoubleBase(s1, s2, point);
    }
  }

  void BenchHashPoint(benchmark::State& state) {
    MPInt p;
    for (auto _ : state) {
      state.PauseTiming();
      MPInt::RandomExactBits(256, &p);
      auto point = ec_->MulBase(p);
      state.ResumeTiming();

      ec_->HashPoint(point);
    }
  }

  void BenchPointEqual(benchmark::State& state) {
    MPInt s;
    for (auto _ : state) {
      state.PauseTiming();
      MPInt::RandomExactBits(256, &s);
      auto p1 = ec_->MulBase(-s);
      auto p2 = ec_->MulBase(s);
      ec_->NegateInplace(&p2);
      state.ResumeTiming();

      ec_->PointEqual(p1, p2);
    }
  }

  void BenchAdd(benchmark::State& state) {
    MPInt s;

    for (auto _ : state) {
      state.PauseTiming();
      MPInt::RandomExactBits(256, &s);
      auto p1 = ec_->MulBase(s);
      state.ResumeTiming();

      ec_->Add(p1, ec_->GetGenerator());
    }
  }

 private:
  std::unique_ptr<EcGroup> ec_;
};

void InitAndRunBenchmarks() {
  static std::vector<EccBencher> benchers;
  std::vector<std::string> curves = absl::StrSplit(
      FLAGS_curve, absl::ByAnyChar(";,.|&+"), absl::SkipWhitespace());
  for (const std::string& curve : curves) {
    if (!FLAGS_lib.empty()) {
      benchers.emplace_back(
          EcGroupFactory::Instance().Create(curve, ArgLib = FLAGS_lib));
      continue;
    }

    for (const auto& lib : EcGroupFactory::Instance().ListLibraries(curve)) {
      benchers.emplace_back(
          EcGroupFactory::Instance().Create(curve, ArgLib = lib));
    }
  }

  for (auto& bencher : benchers) {
    bencher.Register();
  }
}

}  // namespace yacl::crypto::bench

int main(int argc, char** argv) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  benchmark::Initialize(&argc, argv);
  yacl::crypto::bench::InitAndRunBenchmarks();
  benchmark::RunSpecifiedBenchmarks();
  benchmark::Shutdown();
  return 0;
}
