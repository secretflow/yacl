// Copyright 2024 Ant Group Co., Ltd.
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

#include <future>

#include "benchmark/benchmark.h"

#include "yacl/kernel/svole_kernel.h"
#include "yacl/link/test_util.h"

namespace yacl::crypto {

static void BM_SVOLE_single_thread(benchmark::State& state) {
  auto lctxs = link::test::SetupWorld(2);
  for (auto _ : state) {
    state.PauseTiming();
    {
      const size_t num_vole = 1 << 24;
      uint128_t delta = 0;
      std::vector<uint64_t> a(num_vole);
      std::vector<uint128_t> b(num_vole);
      std::vector<uint128_t> c(num_vole);
      SVoleKernel kernel0(SVoleKernel::Role::Sender);
      SVoleKernel kernel1(SVoleKernel::Role::Receiver);

      // WHEN
      state.ResumeTiming();
      auto sender = std::async([&] {
        kernel0.init(lctxs[0]);
        kernel0.eval(lctxs[0], &delta, absl::MakeSpan(c));
      });
      auto receiver = std::async([&] {
        kernel1.init(lctxs[1]);
        kernel1.eval(lctxs[1], absl::MakeSpan(a), absl::MakeSpan(b));
      });
      sender.get();
      receiver.get();
      state.PauseTiming();
    }
    state.ResumeTiming();
  }
}

static void BM_SVOLE_multi_thread(benchmark::State& state) {
  auto lctxs = link::test::SetupWorld(2);
  for (auto _ : state) {
    state.PauseTiming();
    {
      const size_t num_vole = 1 << 24;
      const size_t threads = 16;

      uint128_t delta = 0;
      std::vector<uint64_t> a(num_vole);
      std::vector<uint128_t> b(num_vole);
      std::vector<uint128_t> c(num_vole);
      SVoleKernel kernel0(SVoleKernel::Role::Sender);
      SVoleKernel kernel1(SVoleKernel::Role::Receiver);

      // WHEN
      state.ResumeTiming();
      auto sender = std::async([&] {
        kernel0.init(lctxs[0]);
        kernel0.eval_multithread(lctxs[0], &delta, absl::MakeSpan(c), threads);
      });
      auto receiver = std::async([&] {
        kernel1.init(lctxs[1]);
        kernel1.eval_multithread(lctxs[1], absl::MakeSpan(a), absl::MakeSpan(b),
                                 threads);
      });
      sender.get();
      receiver.get();
      state.PauseTiming();
    }
    state.ResumeTiming();
  }
}

static void BM_SVOLE_streaming(benchmark::State& state) {
  auto lctxs = link::test::SetupWorld(2);
  for (auto _ : state) {
    state.PauseTiming();
    {
      const size_t num_vole = 1 << 24;
      const size_t threads = 16;
      const size_t step_size = 1 << 10;

      uint128_t delta = 0;
      std::vector<uint64_t> a(num_vole);
      std::vector<uint128_t> b(num_vole);
      std::vector<uint128_t> c(num_vole);
      SVoleKernel kernel0(SVoleKernel::Role::Sender);
      SVoleKernel kernel1(SVoleKernel::Role::Receiver);

      // WHEN
      state.ResumeTiming();
      auto sender = std::async([&] {
        kernel0.init(lctxs[0]);
        kernel0.eval_streaming(lctxs[0], &delta, absl::MakeSpan(c), threads,
                               step_size);
      });
      auto receiver = std::async([&] {
        kernel1.init(lctxs[1]);
        kernel1.eval_streaming(lctxs[1], absl::MakeSpan(a), absl::MakeSpan(b),
                               threads, step_size);
      });
      sender.get();
      receiver.get();
      state.PauseTiming();
    }
    state.ResumeTiming();
  }
}
}  // namespace yacl::crypto

BENCHMARK(yacl::crypto::BM_SVOLE_single_thread)
    ->Iterations(1)
    ->Unit(benchmark::kMillisecond);
BENCHMARK(yacl::crypto::BM_SVOLE_multi_thread)
    ->Iterations(1)
    ->Unit(benchmark::kMillisecond);
BENCHMARK(yacl::crypto::BM_SVOLE_streaming)
    ->Iterations(1)
    ->Unit(benchmark::kMillisecond);

BENCHMARK_MAIN();
