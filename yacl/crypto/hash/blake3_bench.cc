// Copyright 2019 Ant Group Co., Ltd.
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
#include <iostream>

#include "benchmark/benchmark.h"

#include "yacl/base/exception.h"
#include "yacl/crypto/hash/blake3.h"

namespace yacl::crypto {

static void BM_Blake3(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);

    state.ResumeTiming();

    for (size_t i = 0; i < n; ++i) {
      Blake3Hash blake3;
      std::vector<uint8_t> hash_result;
      blake3.Update(std::to_string(i));
      hash_result = blake3.CumulativeHash();
    }
  }
}

BENCHMARK(BM_Blake3)
    ->Unit(benchmark::kMillisecond)
    ->Arg(1024)
    ->Arg(5120)
    ->Arg(10240)
    ->Arg(20480)
    ->Arg(40960)
    ->Arg(81920)
    ->Arg(1 << 21);

}  // namespace yacl::crypto
