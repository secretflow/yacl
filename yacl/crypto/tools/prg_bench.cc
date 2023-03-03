// Copyright 2022 Ant Group Co., Ltd.
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

#include "yacl/crypto/base/symmetric_crypto.h"
#include "yacl/crypto/tools/prg.h"

namespace yacl::crypto {

static void BM_Prg(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    Prg<int> prg(0, static_cast<PRG_MODE>(state.range(0)));

    state.ResumeTiming();
    prg();
  }
}

BENCHMARK(BM_Prg)
    ->Arg(0)   // PRG_MODE::kNistAesCtrDrbg
    ->Arg(1)   // PRG_MODE::kGmSm4CtrDrbg
    ->Arg(2)   // PRG_MODE::kAesEcb
    ->Arg(3);  // PRG_MODE::KSm4Ecb

}  // namespace yacl::crypto
