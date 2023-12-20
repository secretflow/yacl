// Copyright 2023 Ant Group Co., Ltd.
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

#include "benchmark.h"

#include <cstdint>

namespace yacl::crypto {

void BM_DefaultArguments(benchmark::internal::Benchmark* b) {
  b->Unit(benchmark::kMillisecond)
      ->Arg(1 << 10)
      ->Arg(1 << 15)
      ->Arg(1 << 20)
      ->Arg(22437250);
}

// Register benchmarks for (Circular) CrHash
BENCHMARK_REGISTER_F(ToolBench, RP)->Apply(BM_DefaultArguments);
BENCHMARK_REGISTER_F(ToolBench, CRHASH)->Apply(BM_DefaultArguments);
BENCHMARK_REGISTER_F(ToolBench, CRHASH_INPLACE)->Apply(BM_DefaultArguments);
BENCHMARK_REGISTER_F(ToolBench, CCRHASH)->Apply(BM_DefaultArguments);
BENCHMARK_REGISTER_F(ToolBench, CCRHASH_INPLACE)->Apply(BM_DefaultArguments);
BENCHMARK_REGISTER_F(ToolBench, RO)->Apply(BM_DefaultArguments);

BENCHMARK_REGISTER_F(ToolBench, PRG)
    ->Unit(benchmark::kMillisecond)
    ->Arg(static_cast<int64_t>(PRG_MODE::kAesEcb))
    ->Arg(static_cast<int64_t>(PRG_MODE::kSm4Ecb));

}  // namespace yacl::crypto
