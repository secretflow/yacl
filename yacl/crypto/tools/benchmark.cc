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

#include "yacl/crypto/tools/benchmark.h"

#include <cstdint>

namespace yacl::crypto {

void BM_DefaultArguments(benchmark::internal::Benchmark* b) {
  b->Unit(benchmark::kMillisecond)->Arg(1 << 10)->Arg(1 << 15)->Arg(1 << 20);
}

// Register benchmarks for local linear code
BENCHMARK_REGISTER_F(ToolBench, LLC)
    ->Unit(benchmark::kMillisecond)
    ->Iterations(10)
    ->Args({10485760, 452000});

// ->Unit(benchmark::kMillisecond)
// ->Arg(1 << 10)
// ->Arg(1 << 15)
// ->Arg(1 << 20);

// BENCHMARK(BM_RP)->Apply(BM_DefaultArguments);
// BENCHMARK(BM_CrHash)->Apply(BM_DefaultArguments);
// BENCHMARK(BM_CcrHash)->Apply(BM_DefaultArguments);
// BENCHMARK(BM_RO)->Apply(BM_DefaultArguments);

// BENCHMARK(BM_Prg)
//     ->Unit(benchmark::kMillisecond)
//     ->Arg(static_cast<int64_t>(PRG_MODE::kNistAesCtrDrbg))
//     ->Arg(static_cast<int64_t>(PRG_MODE::kGmSm4CtrDrbg))
//     ->Arg(static_cast<int64_t>(PRG_MODE::kAesEcb))
//     ->Arg(static_cast<int64_t>(PRG_MODE::KSm4Ecb));

// BENCHMARK(BM_Llc)->Unit(benchmark::kMillisecond)->Args({10485760, 452000});

}  // namespace yacl::crypto
