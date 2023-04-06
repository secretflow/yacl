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

#include "yacl/crypto/base/ecc/ecc_spi.h"

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
        fmt::format("{}/BM_HashPoint", prefix).c_str(),
        [this](benchmark::State& st) { BenchHashPoint(st); });
    benchmark::RegisterBenchmark(
        fmt::format("{}/BM_PointEqual", prefix).c_str(),
        [this](benchmark::State& st) { BenchPointEqual(st); });
    benchmark::RegisterBenchmark(
        fmt::format("{}/BM_Add", prefix).c_str(),
        [this](benchmark::State& st) { BenchAdd(st); });
  }

  void BenchMulBase(benchmark::State& state) {
    MPInt s;
    MPInt::RandomMonicExactBits(state.range(), &s);
    for (auto _ : state) {
      ec_->MulBase(s);
    }
  }

  void BenchMul(benchmark::State& state) {
    MPInt p;
    MPInt::RandomExactBits(256, &p);
    auto point = ec_->MulBase(p);
    MPInt s;
    MPInt::RandomMonicExactBits(state.range(), &s);
    for (auto _ : state) {
      ec_->Mul(point, s);
    }
  }

  void BenchHashPoint(benchmark::State& state) {
    MPInt p;
    MPInt::RandomExactBits(256, &p);
    auto point = ec_->MulBase(p);
    for (auto _ : state) {
      ec_->HashPoint(point);
    }
  }

  void BenchPointEqual(benchmark::State& state) {
    MPInt s;
    MPInt::RandomExactBits(256, &s);
    auto p1 = ec_->MulBase(-s);
    auto p2 = ec_->MulBase(s);
    ec_->NegateInplace(&p2);
    for (auto _ : state) {
      ec_->PointEqual(p1, p2);
    }
  }

  void BenchAdd(benchmark::State& state) {
    MPInt s;
    MPInt::RandomExactBits(256, &s);
    auto p1 = ec_->MulBase(s);
    for (auto _ : state) {
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
      benchers.emplace_back(EcGroupFactory::Create(curve, FLAGS_lib));
      continue;
    }

    for (const auto& lib : EcGroupFactory::ListEcLibraries(curve)) {
      benchers.emplace_back(EcGroupFactory::Create(curve, lib));
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
