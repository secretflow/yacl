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

#include "yacl/crypto/primitives/ot/benchmark.h"

#include <future>
#include <vector>

#include "benchmark/benchmark.h"

#include "yacl/base/exception.h"
#include "yacl/link/test_util.h"

namespace yacl::crypto {

void BM_DefaultArguments(benchmark::internal::Benchmark* b) {
  b->Arg(8192)->Unit(benchmark::kMillisecond);
}

void BM_PerfArguments(benchmark::internal::Benchmark* b) {
  b->Arg(1 << 20)
      ->Arg(1 << 21)
      ->Arg(1 << 22)
      ->Arg(1 << 23)
      ->Arg(1 << 24)
      ->Arg(1 << 25)
      ->Unit(benchmark::kMillisecond)
      ->Iterations(10);
}

BM_REGISTER_ALL_OT(BM_DefaultArguments);

// Equivalent to the following
// BM_REGISTER_SIMPLEST_OT(BM_DefaultArguments);
// BM_REGISTER_IKNP_OTE(BM_DefaultArguments);
// BM_REGISTER_KKRT_OTE(BM_DefaultArguments);
// BM_REGISTER_SGRR_OTE(BM_DefaultArguments);

}  // namespace yacl::crypto
