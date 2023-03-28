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

#include "yacl/crypto/primitives/ot/kkrt_ote.h"

#include <fmt/format.h>
#include <gtest/gtest.h>
#include <spdlog/spdlog.h>

#include <future>
#include <thread>

#include "yacl/base/exception.h"
#include "yacl/crypto/primitives/ot/ot_store.h"
#include "yacl/crypto/tools/prg.h"
#include "yacl/crypto/utils/rand.h"
#include "yacl/link/test_util.h"

namespace yacl::crypto {

struct TestParams {
  unsigned num_ot;
};

class KkrtOtExtTest : public ::testing::TestWithParam<TestParams> {};

TEST_P(KkrtOtExtTest, Works) {
  // GIVEN
  const int kWorldSize = 2;
  auto contexts = link::test::SetupWorld(kWorldSize);

  // KKRT requires 512 width.
  auto base_ot = MockRots(512);

  const size_t num_ot = GetParam().num_ot;
  std::vector<uint128_t> recv_out(num_ot);
  std::vector<uint128_t> inputs(num_ot);
  Prg<uint128_t> prg;
  std::generate(inputs.begin(), inputs.end(),
                [&]() -> uint128_t { return prg(); });

  // WHEN
  std::future<std::unique_ptr<IGroupPRF>> sender = std::async(
      [&] { return KkrtOtExtSend(contexts[0], base_ot.recv, num_ot); });
  std::future<void> receiver = std::async([&] {
    KkrtOtExtRecv(contexts[1], base_ot.send, inputs, absl::MakeSpan(recv_out));
  });
  receiver.get();
  auto encoder = sender.get();

  // THEN
  for (size_t i = 0; i < num_ot; ++i) {
    uint128_t sender_encoded = encoder->Eval(i, inputs[i]);
    uint128_t sender_encoded_other = encoder->Eval(i, prg());
    EXPECT_EQ(sender_encoded, recv_out[i]);
    EXPECT_NE(sender_encoded_other, recv_out[i]);
    EXPECT_NE(sender_encoded, 0);
    EXPECT_NE(sender_encoded_other, 0);
  }
}

INSTANTIATE_TEST_SUITE_P(Works_Instances, KkrtOtExtTest,
                         testing::Values(TestParams{8},     //
                                         TestParams{128},   //
                                         TestParams{129},   //
                                         TestParams{4095},  //
                                         TestParams{4096},  //
                                         TestParams{65536}));

TEST(KkrtOtExtEdgeTest, Test) {
  // GIVEN
  const int kWorldSize = 2;
  auto contexts = link::test::SetupWorld(kWorldSize);
  auto base_ot = MockRots(512);

  size_t kNumOt = 16;
  // WHEN THEN
  {
    // Mismatched receiver.
    std::vector<uint128_t> recv_out(kNumOt);
    auto choices = RandBits<dynamic_bitset<uint128_t>>(kNumOt + 128);
    ASSERT_THROW(
        KkrtOtExtRecv(contexts[1], base_ot.send, absl::MakeConstSpan(choices),
                      absl::MakeSpan(recv_out)),
        yacl::Exception);
  }
  {
    // Empty choice.
    std::vector<uint128_t> recv_out(kNumOt);
    std::vector<uint128_t> choices;
    ASSERT_THROW(
        KkrtOtExtRecv(contexts[1], base_ot.send, absl::MakeConstSpan(choices),
                      absl::MakeSpan(recv_out)),
        yacl::Exception);
  }
  {
    // Empty send output.
    ASSERT_THROW(KkrtOtExtSend(contexts[1], base_ot.recv, 0), yacl::Exception);
  }
}

class KkrtOtExtTest2 : public ::testing::TestWithParam<TestParams> {};
TEST_P(KkrtOtExtTest2, Works) {
  // GIVEN
  const int kWorldSize = 2;
  auto contexts = link::test::SetupWorld(kWorldSize);

  // KKRT requires 512 width.
  auto base_ot = MockRots(512);

  const size_t num_ot = GetParam().num_ot;
  std::vector<uint128_t> recv_out(num_ot);
  std::vector<uint128_t> inputs(num_ot);
  Prg<uint128_t> prg;
  std::generate(inputs.begin(), inputs.end(),
                [&]() -> uint128_t { return prg(); });

  // WHEN
  // std::future<std::unique_ptr<IGroupPRF>> sender =
  //    std::async([&] { return KkrtOtExtSend(contexts[0], recv_opts, num_ot);
  //    });
  KkrtOtExtSender kkrtSender;
  KkrtOtExtReceiver kkrtReceiver;

  std::future<void> send_init =
      std::async([&] { kkrtSender.Init(contexts[0], base_ot.recv, num_ot); });
  std::future<void> recv_init =
      std::async([&] { kkrtReceiver.Init(contexts[1], base_ot.send, num_ot); });
  send_init.get();
  recv_init.get();

  // kkrtSender.setBatchSize(kBatchSize);
  // kkrtReceiver.setBatchSize(kBatchSize);

  size_t batch_size = 896;
  kkrtSender.SetBatchSize(batch_size);
  kkrtReceiver.SetBatchSize(batch_size);
  const size_t num_batch = (num_ot + batch_size - 1) / batch_size;

  std::future<void> receiver = std::async([&] {
    for (size_t batch_idx = 0; batch_idx < num_batch; ++batch_idx) {
      const size_t num_this_batch =
          std::min<size_t>(num_ot - batch_idx * batch_size, batch_size);

      size_t batch_start = batch_idx * batch_size;
      uint128_t receiver_encoded;
      for (size_t i = 0; i < num_this_batch; ++i) {
        kkrtReceiver.Encode(
            batch_start + i, inputs,
            absl::Span<uint8_t>(reinterpret_cast<uint8_t*>(&receiver_encoded),
                                sizeof(uint128_t)));

        recv_out[batch_start + i] = receiver_encoded;
      }
      kkrtReceiver.SendCorrection(contexts[1], num_this_batch);
    }
  });

  std::future<void> sender = std::async([&] {
    for (size_t batch_idx = 0; batch_idx < num_batch; ++batch_idx) {
      const size_t num_this_batch =
          std::min<size_t>(num_ot - batch_idx * batch_size, batch_size);
      kkrtSender.RecvCorrection(contexts[0], num_this_batch);
    }
  });

  receiver.get();
  sender.get();
  auto encoder = kkrtSender.GetOprf();

  // THEN
  for (size_t i = 0; i < num_ot; ++i) {
    uint128_t sender_encoded = encoder->Eval(i, inputs[i]);
    uint128_t sender_encoded_other = encoder->Eval(i, prg());
    EXPECT_EQ(sender_encoded, recv_out[i]);
    EXPECT_NE(sender_encoded_other, recv_out[i]);
    EXPECT_NE(sender_encoded, 0);
    EXPECT_NE(sender_encoded_other, 0);
  }
}

INSTANTIATE_TEST_SUITE_P(Works_Instances2, KkrtOtExtTest2,
                         testing::Values(TestParams{8},     //
                                         TestParams{128},   //
                                         TestParams{129},   //
                                         TestParams{896},   //
                                         TestParams{897},   //
                                         TestParams{4095},  //
                                         TestParams{4096},  //
                                         TestParams{65536}));

}  // namespace yacl::crypto
