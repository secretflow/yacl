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

#include <vector>

#include "benchmark/benchmark.h"

#include "yacl/crypto/base/mpint/mp_int.h"

namespace yacl::crypto::bench {

static std::vector<MPInt> GenerateMPInts(size_t count) {
  std::vector<MPInt> mpints(count);
  for (size_t i = 0; i < count; ++i) {
    MPInt::RandomExactBits(4096, &mpints[i]);
  }
  return mpints;
}

static std::vector<MPInt> mp_ints = GenerateMPInts(1000);

static void BM_MPIntPackingUsingSerialize(benchmark::State& state) {
  int64_t bytes_written = 0;
  for (auto _ : state) {
    for (const auto& mp_int : mp_ints) {
      auto buf = mp_int.Serialize();
      bytes_written += buf.size();
    }
  }
  state.counters["bytes_written"] =
      bytes_written / mp_ints.size() / state.iterations();
}

static void BM_MPIntPackingUsingDeserialize(benchmark::State& state) {
  std::vector<yacl::Buffer> bufs;
  for (const auto& mp_int : mp_ints) {
    bufs.push_back(mp_int.Serialize());
  }

  for (auto _ : state) {
    for (const auto& buf : bufs) {
      MPInt mp_int;
      mp_int.Deserialize(buf);
    }
  }
}

static void BM_MPIntPackingUsingToHexString(benchmark::State& state) {
  int64_t bytes_written = 0;
  for (auto _ : state) {
    for (const auto& mp_int : mp_ints) {
      std::string str = mp_int.ToHexString();
      bytes_written += str.length();
    }
  }
  state.counters["bytes_written"] =
      bytes_written / mp_ints.size() / state.iterations();
}

static void BM_MPIntPackingUsingToBytes(benchmark::State& state) {
  int64_t bytes_written = 0;
  auto byte_count = mp_ints[0].BitCount() / 8;
  for (auto _ : state) {
    for (const auto& mp_int : mp_ints) {
      auto buf = mp_int.ToBytes(byte_count);
      bytes_written += buf.size();
    }
  }
  state.counters["bytes_written"] =
      bytes_written / mp_ints.size() / state.iterations();
}

BENCHMARK(BM_MPIntPackingUsingSerialize)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_MPIntPackingUsingDeserialize)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_MPIntPackingUsingToHexString)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_MPIntPackingUsingToBytes)->Unit(benchmark::kMillisecond);

}  // namespace yacl::crypto::bench

BENCHMARK_MAIN();
