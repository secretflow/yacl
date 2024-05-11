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

#include "yacl/kernel/code/benchmark.h"

namespace yacl::crypto {

void BM_DualEncodeArguments(benchmark::internal::Benchmark* b) {
  b->Unit(benchmark::kMillisecond)
      ->Iterations(10)
      ->Arg(100000)
      ->Arg(1000000)   // one million
      ->Arg(10000000)  // ten million
      ->Arg(22437250);
}

// Register benchmarks for local linear code
BENCHMARK_REGISTER_F(CodeBench, LLC)
    ->Unit(benchmark::kMillisecond)
    ->Iterations(10)
    ->Args({10485760, 452000});

// Register benchmarks for dual LPN
BENCHMARK_REGISTER_F(CodeBench, Silver5)->Apply(BM_DualEncodeArguments);
BENCHMARK_REGISTER_F(CodeBench, Silver5Inplace)->Apply(BM_DualEncodeArguments);
BENCHMARK_REGISTER_F(CodeBench, Silver11)->Apply(BM_DualEncodeArguments);
BENCHMARK_REGISTER_F(CodeBench, Silver11Inplace)->Apply(BM_DualEncodeArguments);
BENCHMARK_REGISTER_F(CodeBench, ExAcc7)->Apply(BM_DualEncodeArguments);
BENCHMARK_REGISTER_F(CodeBench, ExAcc11)->Apply(BM_DualEncodeArguments);
BENCHMARK_REGISTER_F(CodeBench, ExAcc21)->Apply(BM_DualEncodeArguments);
BENCHMARK_REGISTER_F(CodeBench, ExAcc40)->Apply(BM_DualEncodeArguments);

}  // namespace yacl::crypto
