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

#include "mp_vole.h"

#include <gtest/gtest.h>

#include <future>
#include <thread>
#include <utility>
#include <vector>

#include "yacl/base/exception.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/link/test_util.h"
#include "yacl/math/f2k/f2k.h"
#include "yacl/math/gadget.h"

namespace yacl::crypto {

struct TestParams {
  size_t num;
  size_t index_num;
};

class MpVoleTest
    : public ::testing::TestWithParam<std::tuple<bool, bool, TestParams>> {};

using GF64 = uint64_t;
using GF128 = uint128_t;

#define DECLEAR_MPVOLE_TEST(Type0, Type1)                                      \
  TEST_P(MpVoleTest, Type0##x##Type1) {                                        \
    /* setup network */                                                        \
    auto lctxs = link::test::SetupWorld(2);                                    \
    const auto mal = std::get<0>(GetParam());                                  \
    const auto fixed_index = std::get<1>(GetParam());                          \
    const uint64_t num = std::get<2>(GetParam()).num;                          \
    const uint64_t index_num = std::get<2>(GetParam()).index_num;              \
    MpVoleParam param(index_num, num, mal);                                    \
    const auto base_vole_num = param.base_vole_num_;                           \
    param.GenIndexes();                                                        \
    auto delta = static_cast<Type1>(FastRandU128());                           \
    auto pre_a = RandVec<Type0>(base_vole_num);                                \
    auto pre_b = RandVec<Type1>(base_vole_num);                                \
    auto pre_c = RandVec<Type1>(base_vole_num);                                \
    for (size_t i = 0; i < base_vole_num; ++i) {                               \
      pre_c[i] = math::GfMul(delta, pre_a[i]) ^ pre_b[i];                      \
    }                                                                          \
    auto choices = RandBits<dynamic_bitset<uint128_t>>(param.require_ot_num_); \
    param.GenIndexes();                                                        \
    if (fixed_index) {                                                         \
      choices = param.GenChoices();                                            \
    }                                                                          \
    YACL_ENFORCE(choices.size() == param.require_ot_num_);                     \
    auto cot = MockCots(param.require_ot_num_, FastRandU128(), choices);       \
    std::vector<Type0> a(num, 0);                                              \
    std::vector<Type1> b(num, 0);                                              \
    std::vector<Type1> c(num, 0);                                              \
    MpVoleSender<Type0, Type1> mp_sender(param);                               \
    MpVoleReceiver<Type0, Type1> mp_receiver(param);                           \
    mp_sender.OneTimeSetup(delta, std::move(pre_c));                           \
    mp_receiver.OneTimeSetup(std::move(pre_a), std::move(pre_b));              \
    auto sender = std::async([&] {                                             \
      mp_sender.Send(lctxs[0], cot.send, absl::MakeSpan(c), fixed_index);      \
    });                                                                        \
    auto receiver = std::async([&] {                                           \
      mp_receiver.Recv(lctxs[1], cot.recv, absl::MakeSpan(a),                  \
                       absl::MakeSpan(b), fixed_index);                        \
    });                                                                        \
    sender.get();                                                              \
    receiver.get();                                                            \
    std::set<uint32_t> indexes;                                                \
    for (size_t i = 0; i < param.noise_num_; ++i) {                            \
      indexes.insert(i* param.sp_vole_size_ + param.indexes_[i]);              \
    }                                                                          \
    for (uint64_t i = 0; i < num; ++i) {                                       \
      EXPECT_EQ(math::GfMul(delta, a[i]), b[i] ^ c[i]);                        \
    }                                                                          \
  }

DECLEAR_MPVOLE_TEST(GF64, GF64);
DECLEAR_MPVOLE_TEST(GF64, GF128);
DECLEAR_MPVOLE_TEST(GF128, GF128);

INSTANTIATE_TEST_SUITE_P(
    f2kVOLE, MpVoleTest,
    testing::Combine(testing::Values(false,  // false for semi-honest
                                     true),  // true for malicious
                     testing::Values(false,  // false for selected-index
                                     true),  // true for fixed-index
                     testing::Values(TestParams{4, 2},  // edge
                                     TestParams{5, 2},  // edge
                                     TestParams{7, 2},  // edge
                                     TestParams{1 << 8, 64},
                                     TestParams{1 << 10, 257},
                                     TestParams{1 << 20, 1024})),
    [](const testing::TestParamInfo<MpVoleTest::ParamType>& p) {
      return fmt::format(
          "{}_{}_t{}xn{}", std::get<0>(p.param) ? "Mal" : "Semi",
          std::get<1>(p.param) ? "Fixed_index" : "Selected_index",
          std::get<2>(p.param).index_num, std::get<2>(p.param).num);
    });

}  // namespace yacl::crypto
