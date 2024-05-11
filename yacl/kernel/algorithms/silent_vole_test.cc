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

#include "yacl/kernel/algorithms/silent_vole.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <future>
#include <memory>
#include <thread>
#include <utility>
#include <vector>

#include "yacl/base/int128.h"
#include "yacl/link/test_util.h"
#include "yacl/math/f2k/f2k.h"
#include "yacl/math/gadget.h"

namespace yacl::crypto {

class SilentVoleTest
    : public ::testing::TestWithParam<std::tuple<CodeType, size_t, bool>> {};

using GF64 = uint64_t;
using GF128 = uint128_t;

template <typename T, typename K>
void SendWarpper(SilentVoleSender& sender, std::shared_ptr<link::Context>& lctx,
                 absl::Span<K> c) {
  sender.Send(lctx, c);
}

template <>
void SendWarpper<GF64, GF128>(SilentVoleSender& sender,
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

#define DECLARE_SILENT_VOLE_TEST(Type0, Type1)                           \
  TEST_P(SilentVoleTest, Type0##x##Type1) {                              \
    auto lctxs = link::test::SetupWorld(2);                              \
    const auto codetype = std::get<0>(GetParam());                       \
    const auto vole_num = std::get<1>(GetParam());                       \
    const auto is_mal = std::get<2>(GetParam());                         \
    std::vector<Type0> a(vole_num);                                      \
    std::vector<Type1> b(vole_num);                                      \
    std::vector<Type1> c(vole_num);                                      \
    Type1 delta = 0;                                                     \
    auto sender = std::async([&] {                                       \
      auto sv_sender = SilentVoleSender(codetype, is_mal);               \
      SendWarpper<Type0, Type1>(sv_sender, lctxs[0], absl::MakeSpan(c)); \
      delta = sv_sender.GetDelta();                                      \
    });                                                                  \
    auto receiver = std::async([&] {                                     \
      auto sv_receiver = SilentVoleReceiver(codetype, is_mal);           \
      RecvWrapper(sv_receiver, lctxs[1], absl::MakeSpan(a),              \
                  absl::MakeSpan(b));                                    \
    });                                                                  \
    sender.get();                                                        \
    receiver.get();                                                      \
    for (uint64_t i = 0; i < vole_num; ++i) {                            \
      EXPECT_EQ(math::GfMul(a[i], delta) ^ b[i], c[i]);                  \
    }                                                                    \
  }

DECLARE_SILENT_VOLE_TEST(GF64, GF64)
DECLARE_SILENT_VOLE_TEST(GF64, GF128)
DECLARE_SILENT_VOLE_TEST(GF128, GF128)

static std::map<CodeType, std::string> kCodeName = {
    {CodeType::Silver5, "Silver5"}, {CodeType::Silver11, "Silver11"},
    {CodeType::ExAcc7, "ExAcc7"},   {CodeType::ExAcc11, "ExAcc11"},
    {CodeType::ExAcc21, "ExAcc21"}, {CodeType::ExAcc40, "ExAcc40"}};

INSTANTIATE_TEST_SUITE_P(
    f2kVole, SilentVoleTest,
    testing::Combine(testing::Values(CodeType::Silver5, CodeType::Silver11,
                                     CodeType::ExAcc7, CodeType::ExAcc11,
                                     CodeType::ExAcc21,
                                     CodeType::ExAcc40),  // Dual LPN code type
                     testing::Values(64, 1 << 10, 1 << 14,
                                     1 << 18),       // Vole num
                     testing::Values(false, true)),  // Semi-honest or Malicious
    [](const testing::TestParamInfo<SilentVoleTest::ParamType>& p) {
      return fmt::format(
          "{}_{}_{}", std::get<2>(p.param) == true ? "Mal" : "Semi",
          kCodeName[std::get<0>(p.param)], (int)std::get<1>(p.param));
    });

}  // namespace yacl::crypto
