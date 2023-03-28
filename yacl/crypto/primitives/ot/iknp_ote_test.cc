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

#include "yacl/crypto/primitives/ot/iknp_ote.h"

#include <gtest/gtest.h>

#include <future>
#include <memory>
#include <thread>
#include <vector>

#include "yacl/base/exception.h"
#include "yacl/crypto/utils/rand.h"
#include "yacl/link/test_util.h"

namespace yacl::crypto {

struct TestParams {
  unsigned num_ot;
};

class IknpOtExtTest : public ::testing::TestWithParam<TestParams> {};
class IknpCotExtTest : public ::testing::TestWithParam<TestParams> {};

TEST_P(IknpOtExtTest, Works) {
  // GIVEN
  const int kWorldSize = 2;
  const size_t num_ot = GetParam().num_ot;
  auto lctxs = link::test::SetupWorld(kWorldSize);             // setup network
  auto base_ot = MockRots(128);                                // mock base ot
  auto choices = RandBits<dynamic_bitset<uint128_t>>(num_ot);  // get input

  // WHEN
  std::vector<std::array<uint128_t, 2>> send_out(num_ot);
  std::vector<uint128_t> recv_out(num_ot);
  std::future<void> sender = std::async([&] {
    IknpOtExtSend(lctxs[0], base_ot.recv, absl::MakeSpan(send_out), false);
  });
  std::future<void> receiver = std::async([&] {
    IknpOtExtRecv(lctxs[1], base_ot.send, choices, absl::MakeSpan(recv_out),
                  false);
  });
  receiver.get();
  sender.get();

  // THEN
  for (size_t i = 0; i < num_ot; ++i) {
    EXPECT_NE(recv_out[i], 0);
    EXPECT_NE(send_out[i][0], 0);
    EXPECT_NE(send_out[i][1], 0);
    EXPECT_EQ(send_out[i][choices[i]], recv_out[i]);
  }
}

TEST_P(IknpOtExtTest, OtStoreWorks) {
  // GIVEN
  const int kWorldSize = 2;
  const size_t num_ot = GetParam().num_ot;
  auto lctxs = link::test::SetupWorld(kWorldSize);             // setup network
  auto base_ot = MockRots(128);                                // mock base ot
  auto choices = RandBits<dynamic_bitset<uint128_t>>(num_ot);  // get input

  // WHEN
  auto sender =
      std::async([&] { return IknpOtExtSend(lctxs[0], base_ot.recv, num_ot); });
  auto receiver = std::async(
      [&] { return IknpOtExtRecv(lctxs[1], base_ot.send, choices, num_ot); });
  auto recv_out = receiver.get();
  auto send_out = sender.get();

  // THEN
  for (size_t i = 0; i < num_ot; ++i) {
    unsigned idx = choices[i] ? 1 : 0;
    EXPECT_EQ(send_out->GetBlock(i, idx), recv_out->GetBlock(i));
  }
}

TEST_P(IknpCotExtTest, Works) {
  // GIVEN
  const int kWorldSize = 2;
  const size_t num_ot = GetParam().num_ot;
  auto lctxs = link::test::SetupWorld(kWorldSize);             // setup network
  auto base_ot = MockRots(128);                                // mock base ot
  auto choices = RandBits<dynamic_bitset<uint128_t>>(num_ot);  // get input

  // WHEN
  std::vector<std::array<uint128_t, 2>> send_out(num_ot);
  std::vector<uint128_t> recv_out(num_ot);
  std::future<void> sender = std::async([&] {
    IknpOtExtSend(lctxs[0], base_ot.recv, absl::MakeSpan(send_out), true);
  });
  std::future<void> receiver = std::async([&] {
    IknpOtExtRecv(lctxs[1], base_ot.send, choices, absl::MakeSpan(recv_out),
                  true);
  });
  receiver.get();
  sender.get();

  // THEN
  // cot correlation = base ot choice
  uint128_t check = base_ot.recv->CopyChoice().data()[0];
  for (size_t i = 0; i < num_ot; ++i) {
    EXPECT_NE(recv_out[i], 0);
    EXPECT_NE(send_out[i][0], 0);
    EXPECT_NE(send_out[i][1], 0);
    EXPECT_EQ(send_out[i][choices[i]], recv_out[i]);
    EXPECT_EQ(check, send_out[i][0] ^ send_out[i][1]);
  }
}

TEST_P(IknpCotExtTest, OtStoreWorks) {
  // GIVEN
  const int kWorldSize = 2;
  const size_t num_ot = GetParam().num_ot;
  auto lctxs = link::test::SetupWorld(kWorldSize);             // setup network
  auto base_ot = MockRots(128);                                // mock base ot
  auto choices = RandBits<dynamic_bitset<uint128_t>>(num_ot);  // get input

  // WHEN
  auto sender = std::async(
      [&] { return IknpOtExtSend(lctxs[0], base_ot.recv, num_ot, true); });
  auto receiver = std::async([&] {
    return IknpOtExtRecv(lctxs[1], base_ot.send, choices, num_ot, true);
  });
  auto recv_out = receiver.get();
  auto send_out = sender.get();

  // THEN
  // cot correlation = base ot choice
  uint128_t check = base_ot.recv->CopyChoice().data()[0];  // base ot choices
  uint128_t delta = send_out->GetDelta();                  // cot's delta
  EXPECT_EQ(check, delta);
  for (size_t i = 0; i < num_ot; ++i) {
    unsigned idx = choices[i] ? 1 : 0;
    EXPECT_EQ(send_out->GetBlock(i, idx), recv_out->GetBlock(i));
    EXPECT_EQ(check, send_out->GetBlock(i, 0) ^ send_out->GetBlock(i, 1));
  }
}

INSTANTIATE_TEST_SUITE_P(Works_Instances, IknpOtExtTest,
                         testing::Values(TestParams{8},     //
                                         TestParams{128},   //
                                         TestParams{129},   //
                                         TestParams{4095},  //
                                         TestParams{4096},  //
                                         TestParams{65536}));

INSTANTIATE_TEST_SUITE_P(Works_Instances, IknpCotExtTest,
                         testing::Values(TestParams{8},     //
                                         TestParams{128},   //
                                         TestParams{129},   //
                                         TestParams{4095},  //
                                         TestParams{4096},  //
                                         TestParams{65536}));

TEST(IknpOtExtEdgeTest, Test) {
  // GIVEN
  const int kWorldSize = 2;
  const size_t kNumOt = 16;
  auto lctxs = link::test::SetupWorld(kWorldSize);             // setup network
  auto base_ot = MockRots(128);                                // mock base ot
  auto choices = RandBits<dynamic_bitset<uint128_t>>(kNumOt);  // get input

  // WHEN
  {
    // Mismatched receiver.
    std::vector<uint128_t> recv_out(kNumOt);
    auto choices = RandBits<dynamic_bitset<uint128_t>>(kNumOt + 128);
    ASSERT_THROW(IknpOtExtRecv(lctxs[1], base_ot.send, choices,
                               absl::MakeSpan(recv_out)),
                 ::yacl::Exception);
  }
  {
    // Empty choice.
    std::vector<uint128_t> recv_out(kNumOt);
    dynamic_bitset<uint128_t> choices;
    ASSERT_THROW(IknpOtExtRecv(lctxs[1], base_ot.send, choices,
                               absl::MakeSpan(recv_out)),
                 ::yacl::Exception);
  }
  {
    // Empty send output.
    std::vector<std::array<uint128_t, 2>> send_out;
    ASSERT_THROW(
        IknpOtExtSend(lctxs[1], base_ot.recv, absl::MakeSpan(send_out)),
        ::yacl::Exception);
  }
}

}  // namespace yacl::crypto
