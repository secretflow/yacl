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

#include "yacl/kernel/algorithms/kos_ote.h"

#include <gtest/gtest.h>

#include <future>
#include <thread>
#include <utility>
#include <vector>

#include "yacl/base/int128.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/link/test_util.h"

namespace yacl::crypto {

struct TestParams {
  unsigned num_ot;
};

class KosOtExtTest : public ::testing::TestWithParam<TestParams> {};

TEST_P(KosOtExtTest, RotTestWorks) {
  // GIVEN
  const int kWorldSize = 2;
  auto contexts = link::test::SetupWorld(kWorldSize);

  // KOS requires kappa == 128.
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
  uint128_t delta = ot_store.recv.CopyChoice().data()[0];
  uint128_t zero = MakeUint128(0, 0);
  for (size_t i = 0; i < num_ot; ++i) {
    bool choice = choices[i];
    EXPECT_NE(zero, recv_out[i]);
    EXPECT_NE(send_out[i][1 - choice], zero);
    EXPECT_NE(send_out[i][1 - choice], recv_out[i]);

    EXPECT_NE(send_out[i][0] ^ send_out[i][1], delta);  // cot correlation
    EXPECT_EQ(send_out[i][choice], recv_out[i]);        // rot correlation
  }
}

TEST_P(KosOtExtTest, CotTestWorks) {
  // GIVEN
  const int kWorldSize = 2;
  auto contexts = link::test::SetupWorld(kWorldSize);

  // KOS requires kappa == 128.
  auto ot_store = MockRots(128);

  const size_t num_ot = GetParam().num_ot;
  std::vector<std::array<uint128_t, 2>> send_out(num_ot);
  std::vector<uint128_t> recv_out(num_ot);
  const auto choices = RandBits<dynamic_bitset<uint128_t>>(num_ot);

  // WHEN
  std::future<void> sender = std::async([&] {
    KosOtExtSend(contexts[0], ot_store.recv, absl::MakeSpan(send_out), true);
  });
  std::future<void> receiver = std::async([&] {
    KosOtExtRecv(contexts[1], ot_store.send, choices, absl::MakeSpan(recv_out),
                 true);
  });
  receiver.get();
  sender.get();

  // THEN
  uint128_t check = ot_store.recv.CopyChoice().data()[0];
  uint128_t zero = MakeUint128(0, 0);
  for (size_t i = 0; i < num_ot; ++i) {
    bool choice = choices[i];
    EXPECT_NE(zero, recv_out[i]);

    EXPECT_EQ(send_out[i][choice], recv_out[i]);        // rot correlation
    EXPECT_EQ(send_out[i][0] ^ send_out[i][1], check);  // cot correlation
  }
}

TEST_P(KosOtExtTest, OtStoreTestWorks) {
  // GIVEN
  const int kWorldSize = 2;
  auto contexts = link::test::SetupWorld(kWorldSize);

  // KOS requires kappa == 128.
  auto ot_store = MockRots(128);

  const size_t num_ot = GetParam().num_ot;
  const auto choices = RandBits<dynamic_bitset<uint128_t>>(num_ot);

  // WHEN
  auto sender = std::async(
      [&] { return KosOtExtSend(contexts[0], ot_store.recv, num_ot); });
  auto receiver = std::async([&] {
    return KosOtExtRecv(contexts[1], ot_store.send, choices, num_ot);
  });
  auto recv_out = receiver.get();
  auto send_out = sender.get();

  // THEN
  for (size_t i = 0; i < num_ot; ++i) {
    unsigned idx = choices[i] ? 1 : 0;
    EXPECT_EQ(send_out.GetBlock(i, idx), recv_out.GetBlock(i));
  }
}

TEST_P(KosOtExtTest, CotStoreTestWorks) {
  // GIVEN
  const int kWorldSize = 2;
  auto contexts = link::test::SetupWorld(kWorldSize);

  // KOS requires kappa == 128.
  auto ot_store = MockRots(128);

  const size_t num_ot = GetParam().num_ot;
  const auto choices = RandBits<dynamic_bitset<uint128_t>>(num_ot);

  // WHEN
  auto sender = std::async(
      [&] { return KosOtExtSend(contexts[0], ot_store.recv, num_ot, true); });
  auto receiver = std::async([&] {
    return KosOtExtRecv(contexts[1], ot_store.send, choices, num_ot, true);
  });
  auto recv_out = receiver.get();
  auto send_out = sender.get();

  // THEN
  uint128_t check = ot_store.recv.CopyChoice().data()[0];  // base ot choices
  uint128_t delta = send_out.GetDelta();                   // cot's delta
  EXPECT_EQ(check, delta);
  for (size_t i = 0; i < num_ot; ++i) {
    unsigned idx = choices[i] ? 1 : 0;
    EXPECT_EQ(send_out.GetBlock(i, idx), recv_out.GetBlock(i));
    EXPECT_EQ(send_out.GetBlock(i, 0) ^ send_out.GetBlock(i, 1), delta);
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