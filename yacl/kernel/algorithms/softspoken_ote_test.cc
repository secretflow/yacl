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

#include "yacl/kernel/algorithms/softspoken_ote.h"

#include <gtest/gtest.h>

#include <future>
#include <memory>
#include <thread>
#include <vector>

#include "yacl/base/exception.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/kernel/algorithms/ot_store.h"
#include "yacl/link/test_util.h"

namespace yacl::crypto {

struct OtTestParams {
  unsigned num_ot;
  bool mal = false;
  bool compact = false;
};

struct KTestParams {
  unsigned k;
  bool mal = false;
};

struct StepTestParams {
  unsigned step;
  bool mal = false;
};

class SoftspokenStepTest : public ::testing::TestWithParam<StepTestParams> {};
class SoftspokenKTest : public ::testing::TestWithParam<KTestParams> {};
class SoftspokenOtExtTest : public ::testing::TestWithParam<OtTestParams> {};

TEST(SecParamTest, Works) { YACL_PRINT_MODULE_SUMMARY(); }

TEST_P(SoftspokenStepTest, Works) {
  // GIVEN
  const int kWorldSize = 2;
  const size_t step = GetParam().step;
  const bool mal = GetParam().mal;
  const size_t num_ot = 4096;
  auto lctxs = link::test::SetupWorld(kWorldSize);             // setup network
  auto base_ot = MockRots(128);                                // mock option
  auto choices = RandBits<dynamic_bitset<uint128_t>>(num_ot);  // get input

  // WHEN
  std::vector<std::array<uint128_t, 2>> send_out(num_ot);
  std::vector<uint128_t> recv_out(num_ot);
  auto ssSenderTask =
      std::async([&] { return SoftspokenOtExtSender(2, 0, mal); });
  auto ssReceiverTask =
      std::async([&] { return SoftspokenOtExtReceiver(2, 0, mal); });
  auto ssSender = ssSenderTask.get();
  auto ssReceiver = ssReceiverTask.get();

  auto sender = std::async([&] {
    ssSender.OneTimeSetup(lctxs[0], base_ot.recv);
    ssSender.SetStep(step);
    ssSender.Send(lctxs[0], absl::MakeSpan(send_out), true);
  });
  auto receiver = std::async([&] {
    ssReceiver.OneTimeSetup(lctxs[1], base_ot.send);
    ssReceiver.SetStep(step);
    ssReceiver.Recv(lctxs[1], choices, absl::MakeSpan(recv_out), true);
  });
  sender.get();
  receiver.get();
  // THEN
  for (size_t i = 0; i < num_ot; ++i) {
    EXPECT_NE(recv_out[i], 0);
    EXPECT_NE(send_out[i][0], 0);
    EXPECT_NE(send_out[i][1], 0);
    EXPECT_EQ(send_out[i][choices[i]], recv_out[i]);
  }
}

TEST_P(SoftspokenKTest, KWorks) {
  // GIVEN
  const int kWorldSize = 2;
  const size_t k = GetParam().k;
  const bool mal = GetParam().mal;
  const size_t num_ot = 4096;
  auto lctxs = link::test::SetupWorld(kWorldSize);             // setup network
  auto base_ot = MockRots(128);                                // mock option
  auto choices = RandBits<dynamic_bitset<uint128_t>>(num_ot);  // get input

  // WHEN
  std::vector<std::array<uint128_t, 2>> send_out(num_ot);
  std::vector<uint128_t> recv_out(num_ot);
  std::future<void> sender = std::async([&] {
    SoftspokenOtExtSend(lctxs[0], base_ot.recv, absl::MakeSpan(send_out), k,
                        false, mal);
  });
  std::future<void> receiver = std::async([&] {
    SoftspokenOtExtRecv(lctxs[1], base_ot.send, choices,
                        absl::MakeSpan(recv_out), k, false, mal);
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

TEST_P(SoftspokenKTest, ReuseWorks) {
  // GIVEN
  const int kWorldSize = 2;
  const size_t k = GetParam().k;
  const bool mal = GetParam().mal;
  const size_t num_ot = 4096;
  auto lctxs = link::test::SetupWorld(kWorldSize);             // setup network
  auto base_ot = MockRots(128);                                // mock option
  auto choices = RandBits<dynamic_bitset<uint128_t>>(num_ot);  // get input

  // WHEN
  // One time setup for Softspoken
  auto ssReceiverTask =
      std::async([&] { return SoftspokenOtExtReceiver(k, 0, mal); });
  auto ssSenderTask =
      std::async([&] { return SoftspokenOtExtSender(k, 0, mal); });

  auto ssReceiver = ssReceiverTask.get();
  auto ssSender = ssSenderTask.get();

  // Generate COT
  std::vector<std::array<uint128_t, 2>> send_out1(num_ot);
  std::vector<uint128_t> recv_out1(num_ot);
  std::future<void> sendTask1 = std::async([&] {
    ssSender.OneTimeSetup(lctxs[0], base_ot.recv);
    ssSender.Send(lctxs[0], absl::MakeSpan(send_out1), false);
  });
  std::future<void> recvTask1 = std::async([&] {
    ssReceiver.OneTimeSetup(lctxs[1], base_ot.send);
    ssReceiver.Recv(lctxs[1], choices, absl::MakeSpan(recv_out1), false);
  });

  sendTask1.get();
  recvTask1.get();

  // Repeat
  std::vector<std::array<uint128_t, 2>> send_out2(num_ot);
  std::vector<uint128_t> recv_out2(num_ot);
  std::future<void> sendTask2 = std::async(
      [&] { ssSender.Send(lctxs[0], absl::MakeSpan(send_out2), false); });
  std::future<void> recvTask2 = std::async([&] {
    ssReceiver.Recv(lctxs[1], choices, absl::MakeSpan(recv_out2), false);
  });

  sendTask2.get();
  recvTask2.get();

  // THEN
  for (size_t i = 0; i < num_ot; ++i) {
    EXPECT_NE(recv_out1[i], recv_out2[i]);
    EXPECT_NE(send_out1[i][0], send_out2[i][0]);
    EXPECT_NE(send_out1[i][1], send_out2[i][1]);
  }
}

TEST_P(SoftspokenOtExtTest, RotExtWorks) {
  // GIVEN
  const int kWorldSize = 2;
  const size_t num_ot = GetParam().num_ot;
  const bool mal = GetParam().mal;
  const bool compact = GetParam().compact;
  auto lctxs = link::test::SetupWorld(kWorldSize);             // setup network
  auto base_ot = MockRots(128);                                // mock option
  auto choices = RandBits<dynamic_bitset<uint128_t>>(num_ot);  // get input

  // WHEN
  std::vector<std::array<uint128_t, 2>> send_out(num_ot);
  std::vector<uint128_t> recv_out(num_ot);
  std::future<void> sender = std::async([&] {
    SoftspokenOtExtSend(lctxs[0], base_ot.recv, absl::MakeSpan(send_out), 2,
                        false, mal, compact);
  });
  std::future<void> receiver = std::async([&] {
    SoftspokenOtExtRecv(lctxs[1], base_ot.send, choices,
                        absl::MakeSpan(recv_out), 2, false, mal, compact);
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

TEST_P(SoftspokenOtExtTest, CotExtWorks) {
  // GIVEN
  const int kWorldSize = 2;
  const size_t num_ot = GetParam().num_ot;
  const bool mal = GetParam().mal;
  const bool compact = GetParam().compact;
  auto lctxs = link::test::SetupWorld(kWorldSize);             // setup network
  auto base_ot = MockRots(128);                                // mock option
  auto choices = RandBits<dynamic_bitset<uint128_t>>(num_ot);  // get input

  // WHEN
  std::vector<std::array<uint128_t, 2>> send_out(num_ot);
  std::vector<uint128_t> recv_out(num_ot);

  std::future<void> sender = std::async([&] {
    SoftspokenOtExtSend(lctxs[0], base_ot.recv, absl::MakeSpan(send_out), 3,
                        true, mal, compact);
  });
  std::future<void> receiver = std::async([&] {
    SoftspokenOtExtRecv(lctxs[1], base_ot.send, choices,
                        absl::MakeSpan(recv_out), 3, true, mal, compact);
  });
  receiver.get();
  sender.get();

  // THEN
  // cot correlation = base ot choice
  uint128_t check = send_out[0][0] ^ send_out[0][1];
  for (size_t i = 0; i < num_ot; ++i) {
    EXPECT_NE(recv_out[i], 0);
    EXPECT_NE(send_out[i][0], 0);
    EXPECT_NE(send_out[i][1], 0);
    EXPECT_EQ(send_out[i][choices[i]], recv_out[i]);
    EXPECT_EQ(check, send_out[i][0] ^ send_out[i][1]);
    // Compact Mode
    if (compact) {
      EXPECT_EQ(send_out[i][0] & 0x1, 0);
      EXPECT_EQ(send_out[i][1] & 0x1, 1);
      EXPECT_EQ(recv_out[i] & 0x1, choices[i]);
    }
  }
}

TEST_P(SoftspokenOtExtTest, RotStoreWorks) {
  // GIVEN
  const int kWorldSize = 2;
  const size_t num_ot = GetParam().num_ot;
  const bool mal = GetParam().mal;
  const bool compact = GetParam().compact;
  auto lctxs = link::test::SetupWorld(kWorldSize);  // setup network
  auto base_ot = MockRots(128);                     // mock option

  // WHEN
  // One time setup for Softspoken
  auto ssReceiverTask =
      std::async([&] { return SoftspokenOtExtReceiver(2, 0, mal, compact); });
  auto ssSenderTask =
      std::async([&] { return SoftspokenOtExtSender(2, 0, mal, compact); });

  auto ssReceiver = ssReceiverTask.get();
  auto ssSender = ssSenderTask.get();

  // Generate ROT
  std::vector<std::array<uint128_t, 2>> send_out1(num_ot);
  std::vector<uint128_t> recv_out1(num_ot);
  auto sendTask1 = std::async([&] {
    ssSender.OneTimeSetup(lctxs[0], base_ot.recv);
    return ssSender.GenRot(lctxs[0], num_ot);
  });
  auto recvTask1 = std::async([&] {
    ssReceiver.OneTimeSetup(lctxs[1], base_ot.send);
    return ssReceiver.GenRot(lctxs[1], num_ot);
  });

  auto sendStore = sendTask1.get();
  auto recvStore = recvTask1.get();

  EXPECT_EQ(recvStore.Type(), OtStoreType::Normal);
  EXPECT_EQ(sendStore.Type(), OtStoreType::Normal);

  // THEN
  for (size_t i = 0; i < num_ot; ++i) {
    EXPECT_NE(recvStore.GetBlock(i), 0);
    EXPECT_NE(sendStore.GetBlock(i, 0), 0);
    EXPECT_NE(sendStore.GetBlock(i, 1), 0);
    EXPECT_EQ(sendStore.GetBlock(i, recvStore.GetChoice(i)),
              recvStore.GetBlock(i));
  }
}

TEST_P(SoftspokenOtExtTest, CotStoreWorks) {
  // GIVEN
  const int kWorldSize = 2;
  const size_t num_ot = GetParam().num_ot;
  const bool mal = GetParam().mal;
  const bool compact = GetParam().compact;
  auto lctxs = link::test::SetupWorld(kWorldSize);  // setup network
  auto base_ot = MockRots(128);                     // mock option

  // WHEN
  // One time setup for Softspoken
  auto ssReceiverTask =
      std::async([&] { return SoftspokenOtExtReceiver(2, 0, mal, compact); });
  auto ssSenderTask =
      std::async([&] { return SoftspokenOtExtSender(2, 0, mal, compact); });

  auto ssReceiver = ssReceiverTask.get();
  auto ssSender = ssSenderTask.get();

  // Generate COT
  std::vector<std::array<uint128_t, 2>> send_out1(num_ot);
  std::vector<uint128_t> recv_out1(num_ot);
  auto sendTask1 = std::async([&] {
    ssSender.OneTimeSetup(lctxs[0], base_ot.recv);
    return ssSender.GenCot(lctxs[0], num_ot);
  });
  auto recvTask1 = std::async([&] {
    ssReceiver.OneTimeSetup(lctxs[1], base_ot.send);
    return ssReceiver.GenCot(lctxs[1], num_ot);
  });

  auto sendStore = sendTask1.get();
  auto recvStore = recvTask1.get();

  if (compact) {
    EXPECT_EQ(recvStore.Type(), OtStoreType::Compact);
  } else {
    EXPECT_EQ(recvStore.Type(), OtStoreType::Normal);
  }

  EXPECT_EQ(sendStore.Type(), OtStoreType::Compact);
  // THEN
  auto delta = ssSender.GetDelta();
  for (size_t i = 0; i < num_ot; ++i) {
    EXPECT_NE(recvStore.GetBlock(i), 0);
    EXPECT_NE(sendStore.GetBlock(i, 0), 0);
    EXPECT_NE(sendStore.GetBlock(i, 1), 0);
    EXPECT_EQ(sendStore.GetBlock(i, 0) ^ sendStore.GetBlock(i, 1), delta);
    EXPECT_EQ(sendStore.GetBlock(i, recvStore.GetChoice(i)),
              recvStore.GetBlock(i));
    // Compact Mode
    if (compact) {
      EXPECT_EQ(sendStore.GetBlock(i, 0) & 0x1, 0);
      EXPECT_EQ(sendStore.GetBlock(i, 1) & 0x1, 1);
      EXPECT_EQ(recvStore.GetBlock(i) & 0x1, recvStore.GetChoice(i));
    }
  }
}

INSTANTIATE_TEST_SUITE_P(Works_Instances, SoftspokenStepTest,
                         testing::Values(StepTestParams{1},         //
                                         StepTestParams{2},         //
                                         StepTestParams{4},         //
                                         StepTestParams{8},         //
                                         StepTestParams{16},        //
                                         StepTestParams{32},        //
                                         StepTestParams{64},        //
                                         StepTestParams{128},       //
                                         StepTestParams{1, true},   //
                                         StepTestParams{2, true},   //
                                         StepTestParams{4, true},   //
                                         StepTestParams{8, true},   //
                                         StepTestParams{16, true},  //
                                         StepTestParams{32, true},  //
                                         StepTestParams{64, true},  //
                                         StepTestParams{128, true}));

INSTANTIATE_TEST_SUITE_P(Works_Instances, SoftspokenKTest,
                         testing::Values(KTestParams{1},        //
                                         KTestParams{2},        //
                                         KTestParams{3},        //
                                         KTestParams{4},        //
                                         KTestParams{5},        //
                                         KTestParams{6},        //
                                         KTestParams{7},        //
                                         KTestParams{8},        //
                                         KTestParams{9},        //
                                         KTestParams{10},       //
                                         KTestParams{1, true},  //
                                         KTestParams{2, true},  //
                                         KTestParams{3, true},  //
                                         KTestParams{4, true},  //
                                         KTestParams{5, true},  //
                                         KTestParams{6, true},  //
                                         KTestParams{7, true},  //
                                         KTestParams{8, true},  //
                                         KTestParams{9, true},  //
                                         KTestParams{10, true}));

INSTANTIATE_TEST_SUITE_P(Works_Instances, SoftspokenOtExtTest,
                         testing::Values(OtTestParams{8},       //
                                         OtTestParams{128},     //
                                         OtTestParams{129},     //
                                         OtTestParams{4095},    //
                                         OtTestParams{4096},    //
                                         OtTestParams{65536},   //
                                         OtTestParams{100000},  //
                                         //  malicious OT
                                         OtTestParams{8, true},       //
                                         OtTestParams{128, true},     //
                                         OtTestParams{129, true},     //
                                         OtTestParams{4095, true},    //
                                         OtTestParams{4096, true},    //
                                         OtTestParams{65536, true},   //
                                         OtTestParams{100000, true},  //
                                         // malicious && compact OT
                                         OtTestParams{8, true, true},      //
                                         OtTestParams{128, true, true},    //
                                         OtTestParams{129, true, true},    //
                                         OtTestParams{4095, true, true},   //
                                         OtTestParams{4096, true, true},   //
                                         OtTestParams{65536, true, true},  //
                                         OtTestParams{100000, true, true}));

}  // namespace yacl::crypto
