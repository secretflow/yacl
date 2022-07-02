#include "yasl/mpctools/ot/kkrt_ot_extension.h"

#include <fmt/format.h>
#include <gtest/gtest.h>
#include <spdlog/spdlog.h>

#include <future>
#include <thread>

#include "yasl/base/exception.h"
#include "yasl/crypto/pseudo_random_generator.h"
#include "yasl/crypto/utils.h"
#include "yasl/link/test_util.h"

namespace yasl {

struct TestParams {
  unsigned num_ot;
};

class KkrtOtExtTest : public ::testing::TestWithParam<TestParams> {};

std::pair<BaseSendOptions, BaseRecvOptions> MakeBaseOptions(size_t num) {
  BaseSendOptions send_opts;
  BaseRecvOptions recv_opts;
  recv_opts.choices = CreateRandomChoices(num);
  std::random_device rd;
  PseudoRandomGenerator<uint128_t> gen(rd());
  for (size_t i = 0; i < num; ++i) {
    send_opts.blocks.push_back({gen(), gen()});
    recv_opts.blocks.push_back(send_opts.blocks[i][recv_opts.choices[i]]);
  }
  return {std::move(send_opts), std::move(recv_opts)};
}

TEST_P(KkrtOtExtTest, Works) {
  // GIVEN
  const int kWorldSize = 2;
  auto contexts = link::test::SetupWorld(kWorldSize);

  // KKRT requires 512 width.
  BaseSendOptions send_opts;
  BaseRecvOptions recv_opts;
  std::tie(send_opts, recv_opts) = MakeBaseOptions(512);

  const size_t num_ot = GetParam().num_ot;
  std::vector<uint128_t> recv_out(num_ot);
  std::vector<uint128_t> inputs(num_ot);
  PseudoRandomGenerator<uint128_t> prg;
  std::generate(inputs.begin(), inputs.end(),
                [&]() -> uint128_t { return prg(); });

  // WHEN
  std::future<std::unique_ptr<IGroupPRF>> sender =
      std::async([&] { return KkrtOtExtSend(contexts[0], recv_opts, num_ot); });
  std::future<void> receiver = std::async([&] {
    KkrtOtExtRecv(contexts[1], send_opts, inputs, absl::MakeSpan(recv_out));
  });
  receiver.get();
  auto encoder = sender.get();

  // THEN
  for (size_t i = 0; i < num_ot; ++i) {
    uint128_t sender_encoded = encoder->Eval(i, inputs[i]);
    uint128_t sender_encoded_other = encoder->Eval(i, prg());
    EXPECT_EQ(sender_encoded, recv_out[i]);
    EXPECT_NE(sender_encoded_other, recv_out[i]);
  }
}

INSTANTIATE_TEST_SUITE_P(Works_Instances, KkrtOtExtTest,
                         testing::Values(TestParams{8},     //
                                         TestParams{128},   //
                                         TestParams{129},   //
                                         TestParams{4095},  //
                                         TestParams{4096},  //
                                         TestParams{65536}  //
                                         ));

TEST(KkrtOtExtEdgeTest, Test) {
  // GIVEN
  const int kWorldSize = 2;
  auto contexts = link::test::SetupWorld(kWorldSize);

  auto [send_opts, recv_opts] = MakeBaseOptions(512);

  size_t kNumOt = 16;
  // WHEN THEN
  {
    // Mismatched receiver.
    std::vector<uint128_t> recv_out(kNumOt);
    std::vector<uint128_t> choices =
        CreateRandomChoiceBits<uint128_t>(kNumOt + 128);
    ASSERT_THROW(
        KkrtOtExtRecv(contexts[1], send_opts, absl::MakeConstSpan(choices),
                      absl::MakeSpan(recv_out)),
        ::yasl::Exception);
  }
  {
    // Empty choice.
    std::vector<uint128_t> recv_out(kNumOt);
    std::vector<uint128_t> choices;
    ASSERT_THROW(
        KkrtOtExtRecv(contexts[1], send_opts, absl::MakeConstSpan(choices),
                      absl::MakeSpan(recv_out)),
        ::yasl::Exception);
  }
  {
    // Empty send output.
    ASSERT_THROW(KkrtOtExtSend(contexts[1], recv_opts, 0), ::yasl::Exception);
  }
}

class KkrtOtExtTest2 : public ::testing::TestWithParam<TestParams> {};
TEST_P(KkrtOtExtTest2, Works) {
  // GIVEN
  const int kWorldSize = 2;
  auto contexts = link::test::SetupWorld(kWorldSize);

  // KKRT requires 512 width.
  auto [send_opts, recv_opts] = MakeBaseOptions(512);

  const size_t num_ot = GetParam().num_ot;
  std::vector<uint128_t> recv_out(num_ot);
  std::vector<uint128_t> inputs(num_ot);
  PseudoRandomGenerator<uint128_t> prg;
  std::generate(inputs.begin(), inputs.end(),
                [&]() -> uint128_t { return prg(); });

  // WHEN
  // std::future<std::unique_ptr<IGroupPRF>> sender =
  //    std::async([&] { return KkrtOtExtSend(contexts[0], recv_opts, num_ot);
  //    });
  KkrtOtExtSender kkrtSender;
  KkrtOtExtReceiver kkrtReceiver;

  kkrtSender.Init(contexts[0], recv_opts, num_ot);
  kkrtReceiver.Init(contexts[1], send_opts, num_ot);

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
                                         TestParams{65536}  //
                                         ));

}  // namespace yasl
