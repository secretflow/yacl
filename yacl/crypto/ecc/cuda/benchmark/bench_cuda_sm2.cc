// Copyright 2025 Ant Group Co., Ltd.
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

#include <random>
#include <vector>

#include "benchmark/benchmark.h"

#include "yacl/crypto/ecc/cuda/cuda_sm2_group.h"
#include "yacl/crypto/ecc/ecc_spi.h"

namespace yacl::crypto::cuda {
namespace {

class Sm2BenchmarkFixture : public benchmark::Fixture {
 public:
  void SetUp(const benchmark::State&) override {
    if (CudaSm2Group::isGpuAvailable()) {
      cuda_ec_ = EcGroupFactory::Instance().Create("sm2", ArgLib = "CUDA_SM2");
    }
    cpu_ec_ = EcGroupFactory::Instance().Create("sm2", ArgLib = "openssl");
  }

  MPInt randomScalar() {
    MPInt s;
    MPInt::RandomLtN(cpu_ec_->GetOrder(), &s);
    return s;
  }

  EcPoint randomPoint() {
    return cpu_ec_->MulBase(randomScalar());
  }

  std::shared_ptr<EcGroup> cuda_ec_;
  std::shared_ptr<EcGroup> cpu_ec_;
};

BENCHMARK_DEFINE_F(Sm2BenchmarkFixture, CPU_MulBase)(benchmark::State& state) {
  auto scalar = randomScalar();

  for (auto _ : state) {
    auto result = cpu_ec_->MulBase(scalar);
    benchmark::DoNotOptimize(result);
  }

  state.SetItemsProcessed(state.iterations());
}
BENCHMARK_REGISTER_F(Sm2BenchmarkFixture, CPU_MulBase)->Unit(benchmark::kMicrosecond);

BENCHMARK_DEFINE_F(Sm2BenchmarkFixture, CPU_Mul)(benchmark::State& state) {
  auto point = randomPoint();
  auto scalar = randomScalar();

  for (auto _ : state) {
    auto result = cpu_ec_->Mul(point, scalar);
    benchmark::DoNotOptimize(result);
  }

  state.SetItemsProcessed(state.iterations());
}
BENCHMARK_REGISTER_F(Sm2BenchmarkFixture, CPU_Mul)->Unit(benchmark::kMicrosecond);

BENCHMARK_DEFINE_F(Sm2BenchmarkFixture, CPU_Add)(benchmark::State& state) {
  auto p1 = randomPoint();
  auto p2 = randomPoint();

  for (auto _ : state) {
    auto result = cpu_ec_->Add(p1, p2);
    benchmark::DoNotOptimize(result);
  }

  state.SetItemsProcessed(state.iterations());
}
BENCHMARK_REGISTER_F(Sm2BenchmarkFixture, CPU_Add)->Unit(benchmark::kMicrosecond);

BENCHMARK_DEFINE_F(Sm2BenchmarkFixture, CPU_BatchMul)(benchmark::State& state) {
  int count = state.range(0);

  std::vector<EcPoint> points(count);
  std::vector<MPInt> scalars(count);
  for (int i = 0; i < count; ++i) {
    points[i] = randomPoint();
    scalars[i] = randomScalar();
  }

  for (auto _ : state) {
    for (int i = 0; i < count; ++i) {
      auto result = cpu_ec_->Mul(points[i], scalars[i]);
      benchmark::DoNotOptimize(result);
    }
  }

  state.SetItemsProcessed(state.iterations() * count);
}
BENCHMARK_REGISTER_F(Sm2BenchmarkFixture, CPU_BatchMul)
    ->Arg(100)->Arg(1000)->Arg(10000)->Arg(100000)
    ->Unit(benchmark::kMillisecond);

BENCHMARK_DEFINE_F(Sm2BenchmarkFixture, GPU_BatchMulBase)(benchmark::State& state) {
  if (!cuda_ec_) {
    state.SkipWithError("CUDA not available");
    return;
  }

  int count = state.range(0);

  std::vector<MPInt> scalars(count);
  for (int i = 0; i < count; ++i) {
    scalars[i] = randomScalar();
  }
  std::vector<EcPoint> results(count);

  auto* cuda_group = dynamic_cast<CudaSm2Group*>(cuda_ec_.get());

  for (auto _ : state) {
    cuda_group->batchMulBase(scalars, absl::MakeSpan(results));
    benchmark::DoNotOptimize(results);
  }

  state.SetItemsProcessed(state.iterations() * count);
}
BENCHMARK_REGISTER_F(Sm2BenchmarkFixture, GPU_BatchMulBase)
    ->Arg(100)->Arg(1000)->Arg(10000)->Arg(100000)
    ->Unit(benchmark::kMillisecond);
BENCHMARK_REGISTER_F(Sm2BenchmarkFixture, GPU_BatchMulBase)
    ->Name("Sm2BenchmarkFixture/GPU_BatchMulBase_Large")
    ->Arg(1000000)
    ->Unit(benchmark::kMillisecond);

BENCHMARK_DEFINE_F(Sm2BenchmarkFixture, GPU_BatchMul)(benchmark::State& state) {
  if (!cuda_ec_) {
    state.SkipWithError("CUDA not available");
    return;
  }

  int count = state.range(0);

  std::vector<EcPoint> points(count);
  std::vector<MPInt> scalars(count);
  for (int i = 0; i < count; ++i) {
    points[i] = randomPoint();
    scalars[i] = randomScalar();
  }
  std::vector<EcPoint> results(count);

  auto* cuda_group = dynamic_cast<CudaSm2Group*>(cuda_ec_.get());

  for (auto _ : state) {
    cuda_group->batchMul(points, scalars, absl::MakeSpan(results));
    benchmark::DoNotOptimize(results);
  }

  state.SetItemsProcessed(state.iterations() * count);
}
BENCHMARK_REGISTER_F(Sm2BenchmarkFixture, GPU_BatchMul)
    ->Arg(100)->Arg(1000)->Arg(10000)->Arg(100000)
    ->Unit(benchmark::kMillisecond);
BENCHMARK_REGISTER_F(Sm2BenchmarkFixture, GPU_BatchMul)
    ->Name("Sm2BenchmarkFixture/GPU_BatchMul_Large")
    ->Arg(1000000)
    ->Unit(benchmark::kMillisecond);

BENCHMARK_DEFINE_F(Sm2BenchmarkFixture, GPU_BatchMulSameScalar)(benchmark::State& state) {
  if (!cuda_ec_) {
    state.SkipWithError("CUDA not available");
    return;
  }

  int count = state.range(0);
  auto scalar = randomScalar();

  std::vector<EcPoint> points(count);
  for (int i = 0; i < count; ++i) {
    points[i] = randomPoint();
  }
  std::vector<EcPoint> results(count);

  auto* cuda_group = dynamic_cast<CudaSm2Group*>(cuda_ec_.get());

  for (auto _ : state) {
    cuda_group->batchMulSameScalar(points, scalar, absl::MakeSpan(results));
    benchmark::DoNotOptimize(results);
  }

  state.SetItemsProcessed(state.iterations() * count);
}
BENCHMARK_REGISTER_F(Sm2BenchmarkFixture, GPU_BatchMulSameScalar)
    ->Arg(100)->Arg(1000)->Arg(10000)->Arg(100000)
    ->Unit(benchmark::kMillisecond);
BENCHMARK_REGISTER_F(Sm2BenchmarkFixture, GPU_BatchMulSameScalar)
    ->Name("Sm2BenchmarkFixture/GPU_BatchMulSameScalar_Large")
    ->Arg(1000000)
    ->Unit(benchmark::kMillisecond);

BENCHMARK_DEFINE_F(Sm2BenchmarkFixture, GPU_BatchAdd)(benchmark::State& state) {
  if (!cuda_ec_) {
    state.SkipWithError("CUDA not available");
    return;
  }

  int count = state.range(0);

  std::vector<EcPoint> p1s(count);
  std::vector<EcPoint> p2s(count);
  for (int i = 0; i < count; ++i) {
    p1s[i] = randomPoint();
    p2s[i] = randomPoint();
  }
  std::vector<EcPoint> results(count);

  auto* cuda_group = dynamic_cast<CudaSm2Group*>(cuda_ec_.get());

  for (auto _ : state) {
    cuda_group->batchAdd(p1s, p2s, absl::MakeSpan(results));
    benchmark::DoNotOptimize(results);
  }

  state.SetItemsProcessed(state.iterations() * count);
}
BENCHMARK_REGISTER_F(Sm2BenchmarkFixture, GPU_BatchAdd)
    ->Arg(100)->Arg(1000)->Arg(10000)->Arg(100000)
    ->Unit(benchmark::kMillisecond);
BENCHMARK_REGISTER_F(Sm2BenchmarkFixture, GPU_BatchAdd)
    ->Name("Sm2BenchmarkFixture/GPU_BatchAdd_Large")
    ->Arg(1000000)
    ->Unit(benchmark::kMillisecond);

BENCHMARK_DEFINE_F(Sm2BenchmarkFixture, PSI_CPU_HashAndMul)(benchmark::State& state) {
  int count = state.range(0);
  auto scalar = randomScalar();

  std::vector<std::string> inputs(count);
  for (int i = 0; i < count; ++i) {
    inputs[i] = "psi_input_" + std::to_string(i);
  }

  for (auto _ : state) {
    for (int i = 0; i < count; ++i) {
      auto hashed = cpu_ec_->HashToCurve(HashToCurveStrategy::TryAndRehash_SM,
                                         inputs[i], "");
      auto result = cpu_ec_->Mul(hashed, scalar);
      benchmark::DoNotOptimize(result);
    }
  }

  state.SetItemsProcessed(state.iterations() * count);
}
BENCHMARK_REGISTER_F(Sm2BenchmarkFixture, PSI_CPU_HashAndMul)
    ->Arg(100)->Arg(1000)->Arg(10000)->Arg(100000)
    ->Unit(benchmark::kMillisecond);

BENCHMARK_DEFINE_F(Sm2BenchmarkFixture, PSI_GPU_HashAndMul)(benchmark::State& state) {
  if (!cuda_ec_) {
    state.SkipWithError("CUDA not available");
    return;
  }

  int count = state.range(0);
  auto scalar = randomScalar();

  std::vector<std::string> inputs(count);
  std::vector<std::string_view> input_views(count);
  for (int i = 0; i < count; ++i) {
    inputs[i] = "psi_input_" + std::to_string(i);
    input_views[i] = inputs[i];
  }
  std::vector<EcPoint> results(count);

  auto* cuda_group = dynamic_cast<CudaSm2Group*>(cuda_ec_.get());

  for (auto _ : state) {
    cuda_group->batchHashAndMul(HashToCurveStrategy::TryAndRehash_SM,
                                input_views, scalar, absl::MakeSpan(results));
    benchmark::DoNotOptimize(results);
  }

  state.SetItemsProcessed(state.iterations() * count);
}
BENCHMARK_REGISTER_F(Sm2BenchmarkFixture, PSI_GPU_HashAndMul)
    ->Arg(100)->Arg(1000)->Arg(10000)->Arg(100000)
    ->Unit(benchmark::kMillisecond);
BENCHMARK_REGISTER_F(Sm2BenchmarkFixture, PSI_GPU_HashAndMul)
    ->Name("Sm2BenchmarkFixture/PSI_GPU_HashAndMul_Large")
    ->Arg(1000000)
    ->Unit(benchmark::kMillisecond);

// Large-scale correctness verification with sampling
BENCHMARK_DEFINE_F(Sm2BenchmarkFixture, GPU_BatchMulBase_Verified)(benchmark::State& state) {
  if (!cuda_ec_) {
    state.SkipWithError("CUDA not available");
    return;
  }

  int count = state.range(0);
  const int sample_size = 100;  // Verify 100 samples
  const int step = std::max(1, count / sample_size);

  std::vector<MPInt> scalars(count);
  for (int i = 0; i < count; ++i) {
    scalars[i] = randomScalar();
  }
  std::vector<EcPoint> results(count);

  auto* cuda_group = dynamic_cast<CudaSm2Group*>(cuda_ec_.get());

  for (auto _ : state) {
    cuda_group->batchMulBase(scalars, absl::MakeSpan(results));
    benchmark::DoNotOptimize(results);
  }

  // Sample verification after benchmark
  for (int i = 0; i < count; i += step) {
    auto cpu_result = cpu_ec_->MulBase(scalars[i]);
    if (!cuda_ec_->PointEqual(results[i], cpu_result)) {
      state.SkipWithError("Correctness check failed");
      return;
    }
  }

  state.SetItemsProcessed(state.iterations() * count);
}
BENCHMARK_REGISTER_F(Sm2BenchmarkFixture, GPU_BatchMulBase_Verified)
    ->Name("Sm2BenchmarkFixture/GPU_BatchMulBase_Verified_Large")
    ->Arg(1000000)
    ->Unit(benchmark::kMillisecond);

BENCHMARK_DEFINE_F(Sm2BenchmarkFixture, GPU_BatchMul_Verified)(benchmark::State& state) {
  if (!cuda_ec_) {
    state.SkipWithError("CUDA not available");
    return;
  }

  int count = state.range(0);
  const int sample_size = 100;
  const int step = std::max(1, count / sample_size);

  std::vector<EcPoint> points(count);
  std::vector<MPInt> scalars(count);
  for (int i = 0; i < count; ++i) {
    points[i] = randomPoint();
    scalars[i] = randomScalar();
  }
  std::vector<EcPoint> results(count);

  auto* cuda_group = dynamic_cast<CudaSm2Group*>(cuda_ec_.get());

  for (auto _ : state) {
    cuda_group->batchMul(points, scalars, absl::MakeSpan(results));
    benchmark::DoNotOptimize(results);
  }

  for (int i = 0; i < count; i += step) {
    auto cpu_result = cpu_ec_->Mul(points[i], scalars[i]);
    if (!cuda_ec_->PointEqual(results[i], cpu_result)) {
      state.SkipWithError("Correctness check failed");
      return;
    }
  }

  state.SetItemsProcessed(state.iterations() * count);
}
BENCHMARK_REGISTER_F(Sm2BenchmarkFixture, GPU_BatchMul_Verified)
    ->Name("Sm2BenchmarkFixture/GPU_BatchMul_Verified_Large")
    ->Arg(1000000)
    ->Unit(benchmark::kMillisecond);

BENCHMARK_DEFINE_F(Sm2BenchmarkFixture, PSI_GPU_HashAndMul_Verified)(benchmark::State& state) {
  if (!cuda_ec_) {
    state.SkipWithError("CUDA not available");
    return;
  }

  int count = state.range(0);
  const int sample_size = 100;
  const int step = std::max(1, count / sample_size);
  auto scalar = randomScalar();

  std::vector<std::string> inputs(count);
  std::vector<std::string_view> input_views(count);
  for (int i = 0; i < count; ++i) {
    inputs[i] = "psi_input_" + std::to_string(i);
    input_views[i] = inputs[i];
  }
  std::vector<EcPoint> results(count);

  auto* cuda_group = dynamic_cast<CudaSm2Group*>(cuda_ec_.get());

  for (auto _ : state) {
    cuda_group->batchHashAndMul(HashToCurveStrategy::TryAndRehash_SM,
                                input_views, scalar, absl::MakeSpan(results));
    benchmark::DoNotOptimize(results);
  }

  for (int i = 0; i < count; i += step) {
    auto hashed = cpu_ec_->HashToCurve(HashToCurveStrategy::TryAndRehash_SM,
                                       inputs[i], "");
    auto cpu_result = cpu_ec_->Mul(hashed, scalar);
    if (!cuda_ec_->PointEqual(results[i], cpu_result)) {
      state.SkipWithError("Correctness check failed");
      return;
    }
  }

  state.SetItemsProcessed(state.iterations() * count);
}
BENCHMARK_REGISTER_F(Sm2BenchmarkFixture, PSI_GPU_HashAndMul_Verified)
    ->Name("Sm2BenchmarkFixture/PSI_GPU_HashAndMul_Verified_Large")
    ->Arg(1000000)
    ->Unit(benchmark::kMillisecond);

}  // namespace
}  // namespace yacl::crypto::cuda

BENCHMARK_MAIN();
