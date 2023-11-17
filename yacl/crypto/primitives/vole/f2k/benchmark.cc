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

#include <cstdint>
#include <future>
#include <vector>

#include "yacl/base/exception.h"
#include "yacl/crypto/primitives/vole/f2k/base_vole.h"
#include "yacl/crypto/primitives/vole/f2k/silent_vole.h"
#include "yacl/crypto/primitives/vole/f2k/sparse_vole.h"
#include "yacl/link/test_util.h"

//
// bazel run //yacl/crypto/primitives/vole/f2k:benchmark -c opt --
// --benchmark_counters_tabular=true
//
// User Counters:
// 1. recv would record the average time (ms) VoleReceiver is needed.
// 2. send would record the average time (ms) VoleSender is needed.

namespace yacl::crypto {

using GF64 = uint64_t;
using GF128 = uint128_t;

namespace decorator {

// return elapse time (ms)
template <class Function, class... Args>
std::future<double> inline async(Function&& fn, Args&&... args) {
  return std::async([fn, args = std::tuple(std::move(args)...)]() mutable {
    auto start = std::chrono::high_resolution_clock::now();
    std::apply([fn](auto&&... args) { (fn)(std::move(args)...); },
               std::move(args));
    auto end = std::chrono::high_resolution_clock::now();
    auto second =
        std::chrono::duration_cast<std::chrono::duration<double>>(end - start)
            .count();
    return second * 1000;
  });
}

}  // namespace decorator

// VoleBench
class VoleBench : public benchmark::Fixture {
 public:
  void SetUp(const ::benchmark::State&) override {
    if (lctxs_.empty()) {
      lctxs_ = link::test::SetupBrpcWorld(2);
      // lctxs_ = link::test::SetupWorld(2);
    }
  }

  static std::vector<std::shared_ptr<link::Context>> lctxs_;
};

std::vector<std::shared_ptr<link::Context>> VoleBench::lctxs_ = {};

#define DECLARE_GIBLOA_VOLE_BENCH(type0, type1)                                \
  BENCHMARK_DEFINE_F(VoleBench, GilboaVole_##type0##x##type1)                  \
  (benchmark::State & state) {                                                 \
    YACL_ENFORCE(lctxs_.size() == 2);                                          \
    for (auto _ : state) {                                                     \
      state.PauseTiming();                                                     \
      {                                                                        \
        const size_t num_vole = state.range(0);                                \
        auto rot = MockRots(128);                                              \
        std::vector<type0> u(num_vole);                                        \
        std::vector<type1> v(num_vole);                                        \
        std::vector<type1> w(num_vole);                                        \
        state.ResumeTiming();                                                  \
        auto sender = decorator::async([&] {                                   \
          GilboaVoleSend<type0, type1>(lctxs_[0], rot.recv,                    \
                                       absl::MakeSpan(w));                     \
        });                                                                    \
        auto receiver = decorator::async([&] {                                 \
          GilboaVoleRecv<type0, type1>(lctxs_[1], rot.send, absl::MakeSpan(u), \
                                       absl::MakeSpan(v));                     \
        });                                                                    \
        state.counters["send"] += sender.get();                                \
        state.counters["recv"] += receiver.get();                              \
        state.PauseTiming();                                                   \
      }                                                                        \
      state.ResumeTiming();                                                    \
    }                                                                          \
    state.counters["send"] /= state.iterations();                              \
    state.counters["recv"] /= state.iterations();                              \
  }

DECLARE_GIBLOA_VOLE_BENCH(GF64, GF64);
DECLARE_GIBLOA_VOLE_BENCH(GF64, GF128);
DECLARE_GIBLOA_VOLE_BENCH(GF128, GF128);

#define BM_REGISTER_GILBOA_VOLE(Arguments)                                  \
  BENCHMARK_REGISTER_F(VoleBench, GilboaVole_GF64xGF64)->Apply(Arguments);  \
  BENCHMARK_REGISTER_F(VoleBench, GilboaVole_GF64xGF128)->Apply(Arguments); \
  BENCHMARK_REGISTER_F(VoleBench, GilboaVole_GF128xGF128)->Apply(Arguments);

#define DELCARE_SILENT_VOLE_BENCH(CODE, type)                                  \
  BENCHMARK_DEFINE_F(VoleBench, CODE##Vole_##type)(benchmark::State & state) { \
    YACL_ENFORCE(lctxs_.size() == 2);                                          \
    for (auto _ : state) {                                                     \
      state.PauseTiming();                                                     \
      {                                                                        \
        const size_t num_vole = state.range(0);                                \
        std::vector<type> a(num_vole);                                         \
        std::vector<type> b(num_vole);                                         \
        std::vector<type> c(num_vole);                                         \
        auto sender_init = std::async([&] {                                    \
          auto sender = SilentVoleSender(CodeType::CODE);                      \
          /* Execute OneTime Setup */                                          \
          /* sender.OneTimeSetup(lctxs_[0]);  */                               \
          return sender;                                                       \
        });                                                                    \
        auto receiver_init = std::async([&] {                                  \
          auto receiver = SilentVoleReceiver(CodeType::CODE);                  \
          /* Execute OneTime Setup */                                          \
          /* receiver.OneTimeSetup(lctxs_[1]); */                              \
          return receiver;                                                     \
        });                                                                    \
        auto sender = sender_init.get();                                       \
        auto receiver = receiver_init.get();                                   \
        state.ResumeTiming();                                                  \
        auto sender_task = decorator::async(                                   \
            [&] { sender.Send(lctxs_[0], absl::MakeSpan(c)); });               \
        auto receiver_task = decorator::async([&] {                            \
          receiver.Recv(lctxs_[1], absl::MakeSpan(a), absl::MakeSpan(b));      \
        });                                                                    \
        state.counters["send"] += sender_task.get();                           \
        state.counters["recv"] += receiver_task.get();                         \
        state.PauseTiming();                                                   \
      }                                                                        \
      state.ResumeTiming();                                                    \
    }                                                                          \
    state.counters["send"] /= state.iterations();                              \
    state.counters["recv"] /= state.iterations();                              \
  }

DELCARE_SILENT_VOLE_BENCH(Silver5, GF64);
DELCARE_SILENT_VOLE_BENCH(Silver11, GF64);
DELCARE_SILENT_VOLE_BENCH(ExAcc7, GF64);
DELCARE_SILENT_VOLE_BENCH(ExAcc11, GF64);
DELCARE_SILENT_VOLE_BENCH(ExAcc21, GF64);
DELCARE_SILENT_VOLE_BENCH(ExAcc40, GF64);

DELCARE_SILENT_VOLE_BENCH(Silver5, GF128);
DELCARE_SILENT_VOLE_BENCH(Silver11, GF128);
DELCARE_SILENT_VOLE_BENCH(ExAcc7, GF128);
DELCARE_SILENT_VOLE_BENCH(ExAcc11, GF128);
DELCARE_SILENT_VOLE_BENCH(ExAcc21, GF128);
DELCARE_SILENT_VOLE_BENCH(ExAcc40, GF128);

#define DELCARE_SILENT_SUBFIELDVOLE_BENCH(CODE)                             \
  BENCHMARK_DEFINE_F(VoleBench, CODE##SubfieldVole)                         \
  (benchmark::State & state) {                                              \
    YACL_ENFORCE(lctxs_.size() == 2);                                       \
    for (auto _ : state) {                                                  \
      state.PauseTiming();                                                  \
      {                                                                     \
        const size_t num_vole = state.range(0);                             \
        std::vector<uint64_t> a(num_vole);                                  \
        std::vector<uint128_t> b(num_vole);                                 \
        std::vector<uint128_t> c(num_vole);                                 \
        auto sender_init = std::async([&] {                                 \
          auto sender = SilentVoleSender(CodeType::CODE);                   \
          /* Execute OneTime Setup */                                       \
          /* sender.OneTimeSetup(lctxs_[0]);  */                            \
          return sender;                                                    \
        });                                                                 \
        auto receiver_init = std::async([&] {                               \
          auto receiver = SilentVoleReceiver(CodeType::CODE);               \
          /* Execute OneTime Setup */                                       \
          /* receiver.OneTimeSetup(lctxs_[1]); */                           \
          return receiver;                                                  \
        });                                                                 \
        auto sender = sender_init.get();                                    \
        auto receiver = receiver_init.get();                                \
        state.ResumeTiming();                                               \
        auto sender_task = decorator::async(                                \
            [&] { sender.SfSend(lctxs_[0], absl::MakeSpan(c)); });          \
        auto receiver_task = decorator::async([&] {                         \
          receiver.SfRecv(lctxs_[1], absl::MakeSpan(a), absl::MakeSpan(b)); \
        });                                                                 \
        state.counters["send"] += sender_task.get();                        \
        state.counters["recv"] += receiver_task.get();                      \
        state.PauseTiming();                                                \
      }                                                                     \
      state.ResumeTiming();                                                 \
    }                                                                       \
    state.counters["send"] /= state.iterations();                           \
    state.counters["recv"] /= state.iterations();                           \
  }

DELCARE_SILENT_SUBFIELDVOLE_BENCH(Silver5);
DELCARE_SILENT_SUBFIELDVOLE_BENCH(Silver11);
DELCARE_SILENT_SUBFIELDVOLE_BENCH(ExAcc7);
DELCARE_SILENT_SUBFIELDVOLE_BENCH(ExAcc11);
DELCARE_SILENT_SUBFIELDVOLE_BENCH(ExAcc21);
DELCARE_SILENT_SUBFIELDVOLE_BENCH(ExAcc40);

#define BM_REGISTER_SILVER_SILENT_VOLE(Arguments)                         \
  BENCHMARK_REGISTER_F(VoleBench, Silver5Vole_GF128)->Apply(Arguments);   \
  BENCHMARK_REGISTER_F(VoleBench, Silver5Vole_GF64)->Apply(Arguments);    \
  BENCHMARK_REGISTER_F(VoleBench, Silver5SubfieldVole)->Apply(Arguments); \
  BENCHMARK_REGISTER_F(VoleBench, Silver11Vole_GF64)->Apply(Arguments);   \
  BENCHMARK_REGISTER_F(VoleBench, Silver11Vole_GF128)->Apply(Arguments);  \
  BENCHMARK_REGISTER_F(VoleBench, Silver11SubfieldVole)->Apply(Arguments);

#define BM_REGISTER_EXACC_SILENT_VOLE(Arguments)                          \
  BENCHMARK_REGISTER_F(VoleBench, ExAcc7Vole_GF64)->Apply(Arguments);     \
  BENCHMARK_REGISTER_F(VoleBench, ExAcc7Vole_GF128)->Apply(Arguments);    \
  BENCHMARK_REGISTER_F(VoleBench, ExAcc7SubfieldVole)->Apply(Arguments);  \
  BENCHMARK_REGISTER_F(VoleBench, ExAcc11Vole_GF64)->Apply(Arguments);    \
  BENCHMARK_REGISTER_F(VoleBench, ExAcc11Vole_GF128)->Apply(Arguments);   \
  BENCHMARK_REGISTER_F(VoleBench, ExAcc11SubfieldVole)->Apply(Arguments); \
  BENCHMARK_REGISTER_F(VoleBench, ExAcc21Vole_GF64)->Apply(Arguments);    \
  BENCHMARK_REGISTER_F(VoleBench, ExAcc21Vole_GF128)->Apply(Arguments);   \
  BENCHMARK_REGISTER_F(VoleBench, ExAcc21SubfieldVole)->Apply(Arguments); \
  BENCHMARK_REGISTER_F(VoleBench, ExAcc40Vole_GF64)->Apply(Arguments);    \
  BENCHMARK_REGISTER_F(VoleBench, ExAcc40Vole_GF128)->Apply(Arguments);   \
  BENCHMARK_REGISTER_F(VoleBench, ExAcc40SubfieldVole)->Apply(Arguments);

#define BM_REGISTER_ALL_VOLE(Arguments)      \
  BM_REGISTER_GILBOA_VOLE(Arguments);        \
  BM_REGISTER_SILVER_SILENT_VOLE(Arguments); \
  BM_REGISTER_EXACC_SILENT_VOLE(Arguments);

void BM_DefaultArguments(benchmark::internal::Benchmark* b) {
  b->Arg(8192)->Unit(benchmark::kMillisecond);
}

void BM_PerfArguments(benchmark::internal::Benchmark* b) {
  b->Arg(1 << 18)
      ->Arg(1 << 20)  // 1048576, one million
      ->Arg(1 << 22)
      ->Arg(1 << 24)
      ->Arg(10000000)  // ten million
      ->Arg(22437250)
      ->Unit(benchmark::kMillisecond)
      ->Iterations(10);
}

BM_REGISTER_ALL_VOLE(BM_DefaultArguments);

// BM_REGISTER_GILBOA_VOLE(BM_DefaultArguments);
// BM_REGISTER_SILVER_SILENT_VOLE(BM_PerfArguments);
// BM_REGISTER_EXACC_SILENT_VOLE(BM_PerfArguments);

}  // namespace yacl::crypto
