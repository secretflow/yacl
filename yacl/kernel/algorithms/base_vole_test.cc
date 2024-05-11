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

#include "yacl/kernel/algorithms/base_vole.h"

#include <gtest/gtest.h>

#include <future>
#include <thread>
#include <utility>
#include <vector>

#include "yacl/base/exception.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/link/test_util.h"
#include "yacl/math/f2k/f2k.h"
#include "yacl/math/gadget.h"

namespace yacl::crypto {

struct TestParams {
  size_t num;
};

class BaseVoleTest : public ::testing::TestWithParam<TestParams> {};

using GF64 = uint64_t;
using GF128 = uint128_t;

// Semi-honst / Malicious
enum SM : bool { Semi = false, Mal = true };

#define DECLARE_OT2VOLE_TEST(type0, type1)                                \
  TEST_P(BaseVoleTest, Ot2Vole_##type0##x##type1##_Work) {                \
    const uint64_t vole_num = GetParam().num;                             \
    auto delta128 = FastRandU128();                                       \
    auto ot_num = vole_num * sizeof(type0) * 8;                           \
    auto cot = MockCots(ot_num, delta128);                                \
    std::vector<type0> u(vole_num);                                       \
    std::vector<type1> v(vole_num);                                       \
    std::vector<type1> w(vole_num);                                       \
    auto sender = std::async(                                             \
        [&] { Ot2VoleSend<type0, type1>(cot.send, absl::MakeSpan(w)); }); \
    auto receiver = std::async([&] {                                      \
      Ot2VoleRecv<type0, type1>(cot.recv, absl::MakeSpan(u),              \
                                absl::MakeSpan(v));                       \
    });                                                                   \
    sender.get();                                                         \
    receiver.get();                                                       \
    type1 delta = delta128;                                               \
    for (uint64_t i = 0; i < vole_num; ++i) {                             \
      type1 ui = u[i];                                                    \
      EXPECT_EQ(math::GfMul(ui, delta), w[i] ^ v[i]);                     \
    }                                                                     \
  }

DECLARE_OT2VOLE_TEST(GF64, GF64);    // Vole: GF(2^64) x GF(2^64)
DECLARE_OT2VOLE_TEST(GF64, GF128);   // subfield Vole: GF(2^64) x GF(2^128)
DECLARE_OT2VOLE_TEST(GF128, GF128);  // Vole: GF(2^128) x GF(2^128)

#define DECLARE_GILBOAVOLE_TEST(kase, type0, type1)                       \
  TEST_P(BaseVoleTest, kase##_GilboaVole_##type0##x##type1##_Work) {      \
    auto lctxs = link::test::SetupWorld(2);                               \
    const uint64_t vole_num = GetParam().num;                             \
    auto rot = MockRots(128);                                             \
    auto delta128 = rot.recv.CopyChoice().data()[0];                      \
    std::vector<type0> u(vole_num);                                       \
    std::vector<type1> v(vole_num);                                       \
    std::vector<type1> w(vole_num);                                       \
    auto sender = std::async([&] {                                        \
      GilboaVoleSend<type0, type1>(lctxs[0], rot.recv, absl::MakeSpan(w), \
                                   SM::kase);                             \
    });                                                                   \
    auto receiver = std::async([&] {                                      \
      GilboaVoleRecv<type0, type1>(lctxs[1], rot.send, absl::MakeSpan(u), \
                                   absl::MakeSpan(v), SM::kase);          \
    });                                                                   \
    sender.get();                                                         \
    receiver.get();                                                       \
    type1 delta = delta128;                                               \
    for (uint64_t i = 0; i < vole_num; ++i) {                             \
      type1 ui = u[i];                                                    \
      EXPECT_EQ(math::GfMul(ui, delta), w[i] ^ v[i]);                     \
    }                                                                     \
  }

// Semi-honest Base Vole
DECLARE_GILBOAVOLE_TEST(Semi, GF64, GF64);  // Vole: GF(2^64) x GF(2^64)
DECLARE_GILBOAVOLE_TEST(Semi, GF64,
                        GF128);  // subfield Vole: GF(2^64) x GF(2^128)
DECLARE_GILBOAVOLE_TEST(Semi, GF128, GF128);  // Vole: GF(2^128) x GF(2^128)

// Malicious Base Vole
DECLARE_GILBOAVOLE_TEST(Mal, GF64, GF64);  // Vole: GF(2^64) x GF(2^64)
DECLARE_GILBOAVOLE_TEST(Mal, GF64,
                        GF128);  // subfield Vole: GF(2^64) x GF(2^128)
DECLARE_GILBOAVOLE_TEST(Mal, GF128, GF128);  // Vole: GF(2^128) x GF(2^128)

INSTANTIATE_TEST_SUITE_P(f2kVOLE, BaseVoleTest,
                         testing::Values(TestParams{4}, TestParams{5},  //
                                         TestParams{7},                 //
                                         TestParams{1 << 8},
                                         TestParams{1 << 10}));

}  // namespace yacl::crypto
