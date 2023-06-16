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
#include <future>
#include <memory>
#include <vector>

#include "absl/numeric/bits.h"
#include "benchmark/benchmark.h"

#include "yacl/base/exception.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/primitives/ot/base_ot.h"
#include "yacl/crypto/primitives/ot/ferret_ote.h"
#include "yacl/crypto/primitives/ot/gywz_ote.h"
#include "yacl/crypto/primitives/ot/iknp_ote.h"
#include "yacl/crypto/primitives/ot/kkrt_ote.h"
#include "yacl/crypto/primitives/ot/kos_ote.h"
#include "yacl/crypto/primitives/ot/ot_store.h"
#include "yacl/crypto/primitives/ot/sgrr_ote.h"
#include "yacl/crypto/utils/rand.h"
#include "yacl/link/test_util.h"
#include "yacl/utils/matrix_utils.h"

namespace yacl::crypto {

class OtBench : public benchmark::Fixture {
 public:
  void SetUp(const ::benchmark::State& state) override {
    if (lctxs_.empty()) {
      // lctxs_ = link::test::SetupBrpcWorld(2);
      lctxs_ = link::test::SetupWorld(2);
    }
  }

  static std::vector<std::shared_ptr<link::Context>> lctxs_;
};

std::vector<std::shared_ptr<link::Context>> OtBench::lctxs_ = {};

BENCHMARK_DEFINE_F(OtBench, SimplestOT)(benchmark::State& state) {
  YACL_ENFORCE(lctxs_.size() == 2);
  for (auto _ : state) {
    state.PauseTiming();
    {
      const auto num_ot = state.range(0);

      // preprare inputs
      auto choices = RandBits<dynamic_bitset<uint128_t>>(num_ot);
      std::vector<std::array<Block, 2>> send_blocks(num_ot);
      std::vector<Block> recv_blocks(num_ot);

      state.ResumeTiming();

      // run base OT
      auto sender = std::async(
          [&] { BaseOtSend(lctxs_[0], absl::MakeSpan(send_blocks)); });
      auto receiver = std::async(
          [&] { BaseOtRecv(lctxs_[1], choices, absl::MakeSpan(recv_blocks)); });
      sender.get();
      receiver.get();
      state.PauseTiming();
    }
    state.ResumeTiming();
  }
}

BENCHMARK_DEFINE_F(OtBench, IknpOTe)(benchmark::State& state) {
  YACL_ENFORCE(lctxs_.size() == 2);
  for (auto _ : state) {
    state.PauseTiming();
    {
      const auto num_ot = state.range(0);

      // preprare inputs
      std::vector<std::array<uint128_t, 2>> send_blocks(num_ot);
      std::vector<uint128_t> recv_blocks(num_ot);
      auto choices = RandBits<dynamic_bitset<uint128_t>>(num_ot);
      auto base_ot = MockRots(128);

      state.ResumeTiming();

      // run base OT
      auto sender = std::async([&] {
        IknpOtExtSend(lctxs_[0], base_ot.recv, absl::MakeSpan(send_blocks));
      });
      auto receiver = std::async([&] {
        IknpOtExtRecv(lctxs_[1], base_ot.send, choices,
                      absl::MakeSpan(recv_blocks));
      });
      sender.get();
      receiver.get();
      state.PauseTiming();
    }
    state.ResumeTiming();
  }
}

BENCHMARK_DEFINE_F(OtBench, KosOTe)(benchmark::State& state) {
  YACL_ENFORCE(lctxs_.size() == 2);
  for (auto _ : state) {
    state.PauseTiming();
    {
      const auto num_ot = state.range(0);

      // preprare inputs
      std::vector<std::array<uint128_t, 2>> send_blocks(num_ot);
      std::vector<uint128_t> recv_blocks(num_ot);
      auto choices = RandBits<dynamic_bitset<uint128_t>>(num_ot);
      auto base_ot = MockRots(128);

      state.ResumeTiming();

      // run base OT
      auto sender = std::async([&] {
        KosOtExtSend(lctxs_[0], base_ot.recv, absl::MakeSpan(send_blocks));
      });
      auto receiver = std::async([&] {
        KosOtExtRecv(lctxs_[1], base_ot.send, choices,
                     absl::MakeSpan(recv_blocks));
      });
      sender.get();
      receiver.get();
      state.PauseTiming();
    }
    state.ResumeTiming();
  }
}

BENCHMARK_DEFINE_F(OtBench, KkrtOTe)(benchmark::State& state) {
  YACL_ENFORCE(lctxs_.size() == 2);
  for (auto _ : state) {
    state.PauseTiming();
    {
      const auto num_ot = state.range(0);

      // preprare inputs
      std::vector<uint128_t> inputs(num_ot);
      std::vector<uint128_t> recv_out(num_ot);
      auto base_ot = MockRots(512);

      state.ResumeTiming();

      // run base OT
      auto sender =
          std::async([&] { KkrtOtExtSend(lctxs_[0], base_ot.recv, num_ot); });
      auto receiver = std::async([&] {
        KkrtOtExtRecv(lctxs_[1], base_ot.send, inputs,
                      absl::MakeSpan(recv_out));
      });
      sender.get();
      receiver.get();
      state.PauseTiming();
    }
    state.ResumeTiming();
  }
}

BENCHMARK_DEFINE_F(OtBench, SgrrOTe)(benchmark::State& state) {
  YACL_ENFORCE(lctxs_.size() == 2);
  for (auto _ : state) {
    state.PauseTiming();
    {
      const size_t range_n = state.range(0);

      // preprare inputs
      uint32_t choice_value = RandInRange(range_n);
      auto base_ot = MockRots(Log2Ceil(range_n));
      std::vector<uint128_t> send_out(range_n);
      std::vector<uint128_t> recv_out(range_n);

      state.ResumeTiming();

      // run base OT
      auto sender = std::async([&] {
        SgrrOtExtSend(lctxs_[0], base_ot.send, range_n,
                      absl::MakeSpan(send_out));
      });
      auto receiver = std::async([&] {
        SgrrOtExtRecv(lctxs_[1], base_ot.recv, range_n, choice_value,
                      absl::MakeSpan(recv_out));
      });
      sender.get();
      receiver.get();
      state.PauseTiming();
    }
    state.ResumeTiming();
  }
}

BENCHMARK_DEFINE_F(OtBench, GywzOTe)(benchmark::State& state) {
  YACL_ENFORCE(lctxs_.size() == 2);
  for (auto _ : state) {
    state.PauseTiming();
    {
      const size_t range_n = state.range(0);

      // preprare inputs
      uint32_t choice_value = RandInRange(range_n);
      uint128_t delta = SecureRandSeed();
      auto base_ot = MockCots(Log2Ceil(range_n), delta);
      std::vector<uint128_t> send_out(range_n);
      std::vector<uint128_t> recv_out(range_n);

      state.ResumeTiming();

      // run base OT
      auto sender = std::async([&] {
        GywzOtExtSend(lctxs_[0], base_ot.send, range_n,
                      absl::MakeSpan(send_out));
      });
      auto receiver = std::async([&] {
        GywzOtExtRecv(lctxs_[1], base_ot.recv, range_n, choice_value,
                      absl::MakeSpan(recv_out));
      });
      sender.get();
      receiver.get();
      state.PauseTiming();
    }
    state.ResumeTiming();
  }
}

BENCHMARK_DEFINE_F(OtBench, FerretOTe)(benchmark::State& state) {
  YACL_ENFORCE(lctxs_.size() == 2);
  for (auto _ : state) {
    state.PauseTiming();
    {
      const size_t num_ot = state.range(0);

      // preprare inputs
      auto option =
          MakeFerretOtExtOption(LpnParam::GetDefault(), num_ot);  // make option
      auto cots = MockCompactOts(option.cot_num);  // mock base ot
      dynamic_bitset<uint128_t> choice;

      state.ResumeTiming();

      // run base OT
      auto sender = std::async(
          [&] { FerretOtExtSend(lctxs_[0], cots.send, option, num_ot); });
      auto receiver = std::async(
          [&] { FerretOtExtRecv(lctxs_[1], cots.recv, option, num_ot); });
      sender.get();
      receiver.get();
      state.PauseTiming();
    }
    state.ResumeTiming();
  }
}

#define BM_REGISTER_SIMPLEST_OT(Arguments) \
  BENCHMARK_REGISTER_F(OtBench, SimplestOT)->Apply(Arguments);

#define BM_REGISTER_IKNP_OTE(Arguments) \
  BENCHMARK_REGISTER_F(OtBench, IknpOTe)->Apply(Arguments);

#define BM_REGISTER_KOS_OTE(Arguments) \
  BENCHMARK_REGISTER_F(OtBench, KosOTe)->Apply(Arguments);

#define BM_REGISTER_KKRT_OTE(Arguments) \
  BENCHMARK_REGISTER_F(OtBench, KkrtOTe)->Apply(Arguments);

#define BM_REGISTER_SGRR_OTE(Arguments) \
  BENCHMARK_REGISTER_F(OtBench, SgrrOTe)->Apply(Arguments);

#define BM_REGISTER_GYWZ_OTE(Arguments) \
  BENCHMARK_REGISTER_F(OtBench, GywzOTe)->Apply(Arguments);

#define BM_REGISTER_FERRET_OTE(Arguments) \
  BENCHMARK_REGISTER_F(OtBench, FerretOTe)->Apply(Arguments);

#define BM_REGISTER_ALL_OT(Arguments) \
  BM_REGISTER_SIMPLEST_OT(Arguments)  \
  BM_REGISTER_IKNP_OTE(Arguments)     \
  BM_REGISTER_KOS_OTE(Arguments)      \
  BM_REGISTER_KKRT_OTE(Arguments)     \
  BM_REGISTER_SGRR_OTE(Arguments)     \
  BM_REGISTER_GYWZ_OTE(Arguments)     \
  BM_REGISTER_FERRET_OTE(Arguments)
}  // namespace yacl::crypto
