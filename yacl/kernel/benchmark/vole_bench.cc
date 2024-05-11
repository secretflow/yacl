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

#include <cstdint>
#include <future>
#include <vector>

#include "benchmark/benchmark.h"

#include "yacl/base/exception.h"
#include "yacl/kernel/algorithms/base_vole.h"
#include "yacl/kernel/algorithms/silent_vole.h"
#include "yacl/link/test_util.h"

//
// bazel run //yacl/kernelle/f2k:benchmark -c opt --
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

// Wrapper
template <typename T, typename K>
void SendWrapper(SilentVoleSender& sender, std::shared_ptr<link::Context>& lctx,
                 absl::Span<K> c) {
  sender.Send(lctx, c);
}

template <>
void SendWrapper<GF64, GF128>(SilentVoleSender& sender,
                              std::shared_ptr<link::Context>& lctx,
                              absl::Span<GF128> c) {
  sender.SfSend(lctx, c);
}

template <typename T, typename K>
void RecvWrapper(SilentVoleReceiver& receiver,
                 std::shared_ptr<link::Context>& lctx, absl::Span<T> a,
                 absl::Span<K> b) {
  receiver.Recv(lctx, a, b);
}

template <>
void RecvWrapper<GF64, GF128>(SilentVoleReceiver& receiver,
                              std::shared_ptr<link::Context>& lctx,
                              absl::Span<GF64> a, absl::Span<GF128> b) {
  receiver.SfRecv(lctx, a, b);
}

class StaticLink {
 public:
  static std::vector<std::shared_ptr<link::Context>> GetLinks() {
    if (lctxs_.empty()) {
      // lctxs_ = link::test::SetupBrpcWorld(2);
      lctxs_ = link::test::SetupWorld(2);
    }
    return lctxs_;
  }
  static std::vector<std::shared_ptr<link::Context>> lctxs_;
};

std::vector<std::shared_ptr<link::Context>> StaticLink::lctxs_ = {};

// Gilboa Vole (Semi-honset/Mal, Type0 , Type1)
template <class... Args>
void GilboaVoleBench(benchmark::State& state, Args&&... args) {
  auto lctxs = StaticLink::GetLinks();
  YACL_ENFORCE(lctxs.size() == 2);

  auto param = std::forward_as_tuple(args...);
  bool mal = std::get<0>(param);

  using T = std::decay_t<decltype(std::get<1>(param))>;
  using K = std::decay_t<decltype(std::get<2>(param))>;
  for (auto _ : state) {
    state.PauseTiming();
    {
      const size_t num_vole = state.range(0);
      auto rot = MockRots(128);
      std::vector<T> u(num_vole);
      std::vector<K> v(num_vole);
      std::vector<K> w(num_vole);
      uint64_t send_byte = 0;
      uint64_t recv_byte = 0;
      send_byte -= lctxs[0]->GetStats()->sent_bytes;
      recv_byte -= lctxs[0]->GetStats()->recv_bytes;
      state.ResumeTiming();
      auto sender = decorator::async([&] {
        GilboaVoleSend<T, K>(lctxs[0], rot.recv, absl::MakeSpan(w), mal);
      });
      auto receiver = decorator::async([&] {
        GilboaVoleRecv<T, K>(lctxs[1], rot.send, absl::MakeSpan(u),
                             absl::MakeSpan(v), mal);
      });
      state.counters["send"] += sender.get();
      state.counters["recv"] += receiver.get();
      state.PauseTiming();
      send_byte += lctxs[0]->GetStats()->sent_bytes;
      recv_byte += lctxs[0]->GetStats()->recv_bytes;
      state.counters["send_byte"] += send_byte;
      state.counters["recv_byte"] += recv_byte;
    }
    state.ResumeTiming();
  }
  state.counters["send"] /= state.iterations();
  state.counters["recv"] /= state.iterations();
  state.counters["send_byte"] /= state.iterations();
  state.counters["recv_byte"] /= state.iterations();
}

// Silent Vole (Codetype, Semi-honset/Mal, Type0 , Type1)
template <class... Args>
void SilentVoleBench(benchmark::State& state, Args&&... args) {
  auto lctxs = StaticLink::GetLinks();
  YACL_ENFORCE(lctxs.size() == 2);
  auto param = std::forward_as_tuple(args...);
  CodeType codetype = std::get<0>(param);
  bool mal = std::get<1>(param);

  using T = std::decay_t<decltype(std::get<2>(param))>;
  using K = std::decay_t<decltype(std::get<3>(param))>;

  for (auto _ : state) {
    state.PauseTiming();
    {
      const size_t num_vole = state.range(0);
      std::vector<T> a(num_vole);
      std::vector<K> b(num_vole);
      std::vector<K> c(num_vole);
      auto sender_init = std::async([&] {
        auto sender = SilentVoleSender(codetype, mal);
        return sender;
      });
      auto receiver_init = std::async([&] {
        auto receiver = SilentVoleReceiver(codetype, mal);
        return receiver;
      });
      auto sender = sender_init.get();
      auto receiver = receiver_init.get();

      uint64_t send_byte = 0;
      uint64_t recv_byte = 0;
      send_byte -= lctxs[0]->GetStats()->sent_bytes;
      recv_byte -= lctxs[0]->GetStats()->recv_bytes;

      state.ResumeTiming();
      auto sender_task = decorator::async(
          [&] { SendWrapper<T, K>(sender, lctxs[0], absl::MakeSpan(c)); });
      auto receiver_task = decorator::async([&] {
        RecvWrapper<T, K>(receiver, lctxs[1], absl::MakeSpan(a),
                          absl::MakeSpan(b));
      });
      state.counters["send"] += sender_task.get();
      state.counters["recv"] += receiver_task.get();
      state.PauseTiming();
      send_byte += lctxs[0]->GetStats()->sent_bytes;
      recv_byte += lctxs[0]->GetStats()->recv_bytes;
      state.counters["send_byte"] += send_byte;
      state.counters["recv_byte"] += recv_byte;
    }
    state.ResumeTiming();
  }
  state.counters["send"] /= state.iterations();
  state.counters["recv"] /= state.iterations();
  state.counters["send_byte"] /= state.iterations();
  state.counters["recv_byte"] /= state.iterations();
}

#define Zero(name) name(0)
#define GF64 uint64_t
#define GF128 uint128_t

enum SM : bool { Semi = false, Mal = true };

#define GILBOA_VOLE_BM_TEMPLATE(kase, type0, type1, Arguments)          \
  BENCHMARK_CAPTURE(GilboaVoleBench, kase##_BaseVole_##type0##x##type1, \
                    SM::kase, Zero(type0), Zero(type1))                 \
      ->Apply(Arguments);

#define SM_GILBOA_VOLE_BM_TEMPLATE(kase, Arguments)     \
  GILBOA_VOLE_BM_TEMPLATE(kase, GF64, GF64, Arguments)  \
  GILBOA_VOLE_BM_TEMPLATE(kase, GF64, GF128, Arguments) \
  GILBOA_VOLE_BM_TEMPLATE(kase, GF128, GF128, Arguments)

#define DECLARE_GILBOA_VOLE_BM(Arguments)     \
  SM_GILBOA_VOLE_BM_TEMPLATE(Semi, Arguments) \
  SM_GILBOA_VOLE_BM_TEMPLATE(Mal, Arguments)

#define SILENT_VOLE_BM_TEMPLATE(Code, kase, type0, type1, Arguments)    \
  BENCHMARK_CAPTURE(SilentVoleBench, kase##_##Code##_##type0##x##type1, \
                    CodeType::Code, SM::kase, Zero(type0), Zero(type1)) \
      ->Apply(Arguments);

#define SM_SILENT_VOLE_BM_TEMPLATE(Code, kase, Arguments)     \
  SILENT_VOLE_BM_TEMPLATE(Code, kase, GF64, GF64, Arguments)  \
  SILENT_VOLE_BM_TEMPLATE(Code, kase, GF64, GF128, Arguments) \
  SILENT_VOLE_BM_TEMPLATE(Code, kase, GF128, GF128, Arguments)

#define DECLARE_SPECIFIC_SILENT_VOLE_BM(Code, Arguments) \
  SM_SILENT_VOLE_BM_TEMPLATE(Code, Semi, Arguments)      \
  SM_SILENT_VOLE_BM_TEMPLATE(Code, Mal, Arguments)

#define DECLARE_SILVER_VOLE_BM(Arguments)             \
  DECLARE_SPECIFIC_SILENT_VOLE_BM(Silver5, Arguments) \
  DECLARE_SPECIFIC_SILENT_VOLE_BM(Silver11, Arguments)

#define DECLARE_EXACC_VOLE_BM(Arguments)              \
  DECLARE_SPECIFIC_SILENT_VOLE_BM(ExAcc7, Arguments)  \
  DECLARE_SPECIFIC_SILENT_VOLE_BM(ExAcc11, Arguments) \
  DECLARE_SPECIFIC_SILENT_VOLE_BM(ExAcc21, Arguments) \
  DECLARE_SPECIFIC_SILENT_VOLE_BM(ExAcc40, Arguments)

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

DECLARE_GILBOA_VOLE_BM(BM_DefaultArguments)
DECLARE_SILVER_VOLE_BM(BM_PerfArguments)
DECLARE_EXACC_VOLE_BM(BM_PerfArguments)

}  // namespace yacl::crypto
