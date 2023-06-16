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

#include "yacl/crypto/primitives/ot/kos_ote.h"

#include <gtest/gtest.h>

#include <future>
#include <thread>
#include <utility>
#include <vector>

#include "yacl/crypto/utils/rand.h"
#include "yacl/link/test_util.h"

namespace yacl::crypto {

struct TestParams {
  unsigned num_ot;
};

class KosOtExtTest : public ::testing::TestWithParam<TestParams> {};

TEST_P(KosOtExtTest, Works) {
  // GIVEN
  const int kWorldSize = 2;
  auto contexts = link::test::SetupWorld(kWorldSize);

  // IKNP requires kappa == 128.
  auto ot_store = MockRots(128);

  const size_t num_ot = GetParam().num_ot;
  std::vector<std::array<uint128_t, 2>> send_out(num_ot);
  std::vector<uint128_t> recv_out(num_ot);
  const auto choices = RandBits<dynamic_bitset<uint128_t>>(num_ot);

  // WHEN
  std::future<void> sender = std::async([&] {
    KosOtExtSend(contexts[0], ot_store.recv, absl::MakeSpan(send_out));
  });
  std::future<void> receiver = std::async([&] {
    KosOtExtRecv(contexts[1], ot_store.send, choices, absl::MakeSpan(recv_out));
  });
  receiver.get();
  sender.get();

  // THEN
  for (size_t i = 0; i < num_ot; ++i) {
    bool choice = choices[i];
    EXPECT_EQ(send_out[i][choice], recv_out[i]);
  }
}

INSTANTIATE_TEST_SUITE_P(Works_Instances, KosOtExtTest,
                         testing::Values(TestParams{8},          // 0
                                         TestParams{128},        // 1
                                         TestParams{129},        // 2
                                         TestParams{4095},       // 3
                                         TestParams{4096},       // 4
                                         TestParams{65536},      // 5
                                         TestParams{1 << 10},    // 6
                                         TestParams{1 << 15}));  // 7

TEST(KosOtExtEdgeTest, Test) {
  // GIVEN
  const int kWorldSize = 2;
  auto contexts = link::test::SetupWorld(kWorldSize);

  auto ot_store = MockRots(128);

  size_t kNumOt = 16;
  // WHEN THEN
  {
    // Mismatched receiver.
    std::vector<uint128_t> recv_out(kNumOt);
    auto choices = RandBits<dynamic_bitset<uint128_t>>(kNumOt + 128);
    ASSERT_THROW(KosOtExtRecv(contexts[1], ot_store.send, choices,
                              absl::MakeSpan(recv_out)),
                 ::yacl::Exception);
  }
  {
    // Empty choice.
    std::vector<uint128_t> recv_out(kNumOt);
    dynamic_bitset<uint128_t> choices;
    ASSERT_THROW(KosOtExtRecv(contexts[1], ot_store.send, choices,
                              absl::MakeSpan(recv_out)),
                 ::yacl::Exception);
  }
  {
    // Empty send output.
    std::vector<std::array<uint128_t, 2>> send_out;
    ASSERT_THROW(
        KosOtExtSend(contexts[1], ot_store.recv, absl::MakeSpan(send_out)),
        ::yacl::Exception);
  }
}

}  // namespace yacl::crypto
