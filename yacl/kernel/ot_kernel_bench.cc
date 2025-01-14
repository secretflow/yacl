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

#include "benchmark/benchmark.h"

#include "yacl/kernel/ot_kernel.h"
#include "yacl/link/test_util.h"

namespace yacl::crypto {

static void BM_Ferret_OT_single_thread(benchmark::State& state) {
  auto lctxs = link::test::SetupWorld(2);
  for (auto _ : state) {
    state.PauseTiming();
    {
      const size_t num_ot = state.range(0);
      OtSendStore ot_send(num_ot, OtStoreType::Compact);  // placeholder
      OtRecvStore ot_recv(num_ot, OtStoreType::Compact);  // placeholder

      OtKernel kernel0(OtKernel::Role::Sender, OtKernel::ExtAlgorithm::Ferret);
      OtKernel kernel1(OtKernel::Role::Receiver,
                       OtKernel::ExtAlgorithm::Ferret);

      // WHEN
      state.ResumeTiming();
      auto sender = std::async([&] {
        kernel0.init(lctxs[0]);
        kernel0.eval_cot_random_choice(lctxs[0], num_ot, &ot_send);
      });
      auto receiver = std::async([&] {
        kernel1.init(lctxs[1]);
        kernel1.eval_cot_random_choice(lctxs[1], num_ot, &ot_recv);
      });
      sender.get();
      receiver.get();
      state.PauseTiming();
    }
    state.ResumeTiming();
  }
}

static void BM_SoftSpoken_OT_single_thread(benchmark::State& state) {
  auto lctxs = link::test::SetupWorld(2);
  for (auto _ : state) {
    state.PauseTiming();
    {
      const size_t num_ot = state.range(0);
      OtSendStore ot_send(num_ot, OtStoreType::Compact);  // placeholder
      OtRecvStore ot_recv(num_ot, OtStoreType::Compact);  // placeholder
      OtKernel kernel0(OtKernel::Role::Sender,
                       OtKernel::ExtAlgorithm::SoftSpoken);
      OtKernel kernel1(OtKernel::Role::Receiver,
                       OtKernel::ExtAlgorithm::SoftSpoken);

      // WHEN
      state.ResumeTiming();
      auto sender = std::async([&] {
        kernel0.init(lctxs[0]);
        kernel0.eval_cot_random_choice(lctxs[0], num_ot, &ot_send);
      });
      auto receiver = std::async([&] {
        kernel1.init(lctxs[1]);
        kernel1.eval_cot_random_choice(lctxs[1], num_ot, &ot_recv);
      });
      sender.get();
      receiver.get();
      state.PauseTiming();
    }
    state.ResumeTiming();
  }
}
}  // namespace yacl::crypto

BENCHMARK(yacl::crypto::BM_Ferret_OT_single_thread)
    ->Iterations(1)
    ->Arg(1 << 20)
    ->Arg(1 << 22)
    ->Arg(1 << 24)
    ->Arg(1 << 26)
    ->Unit(benchmark::kMillisecond);

BENCHMARK(yacl::crypto::BM_SoftSpoken_OT_single_thread)
    ->Iterations(1)
    ->Arg(1 << 20)
    ->Arg(1 << 22)
    ->Arg(1 << 24)
    ->Arg(1 << 26)
    ->Unit(benchmark::kMillisecond);

BENCHMARK_MAIN();
