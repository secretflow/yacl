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

#include <fmt/format.h>
#include <gtest/gtest.h>
#include <spdlog/spdlog.h>

#include <future>
#include <thread>

#include "yacl/base/exception.h"
#include "yacl/crypto/tools/prg.h"
#include "yacl/crypto/utils/rand.h"
#include "yacl/link/test_util.h"

namespace yacl {

struct TestParams {
  unsigned num_ot;
};

int GetBit(const std::vector<uint128_t>& choices, size_t idx) {
  uint128_t mask = uint128_t(1) << (idx & 127);
  return (choices[idx / 128] & mask) ? 1 : 0;
}

class IknpOtExtTest : public ::testing::TestWithParam<TestParams> {};

std::pair<BaseOtSendStore, BaseOtRecvStore> MakeBaseOptions(size_t num) {
  BaseOtSendStore send_opts;
  BaseOtRecvStore recv_opts;
  recv_opts.choices = crypto::RandBits(num);
  std::random_device rd;
  Prg<uint128_t> gen(rd());
  for (size_t i = 0; i < num; ++i) {
    send_opts.blocks.push_back({gen(), gen()});
    recv_opts.blocks.push_back(send_opts.blocks[i][recv_opts.choices[i]]);
  }
  return {std::move(send_opts), std::move(recv_opts)};
}

TEST_P(IknpOtExtTest, Works) {
  // GIVEN
  const int kWorldSize = 2;
  auto contexts = link::test::SetupWorld(kWorldSize);

  // IKNP requires kappa == 128.
  BaseOtSendStore send_opts;
  BaseOtRecvStore recv_opts;
  std::tie(send_opts, recv_opts) = MakeBaseOptions(128);

  const size_t num_ot = GetParam().num_ot;
  std::vector<std::array<uint128_t, 2>> send_out(num_ot);
  std::vector<uint128_t> recv_out(num_ot);
  constexpr int kNumBits = sizeof(uint128_t) * 8;
  size_t block_num = (num_ot + kNumBits - 1) / kNumBits;
  std::vector<uint128_t> choices = crypto::RandVec<uint128_t>(block_num);

  // WHEN
  std::future<void> sender = std::async(
      [&] { IknpOtExtSend(contexts[0], recv_opts, absl::MakeSpan(send_out)); });
  std::future<void> receiver = std::async([&] {
    IknpOtExtRecv(contexts[1], send_opts, absl::MakeConstSpan(choices),
                  absl::MakeSpan(recv_out));
  });
  receiver.get();
  sender.get();

  // THEN
  for (size_t i = 0; i < num_ot; ++i) {
    int choice = GetBit(choices, i);
    EXPECT_EQ(send_out[i][choice], recv_out[i]);
  }
}

INSTANTIATE_TEST_SUITE_P(Works_Instances, IknpOtExtTest,
                         testing::Values(TestParams{8},     //
                                         TestParams{128},   //
                                         TestParams{129},   //
                                         TestParams{4095},  //
                                         TestParams{4096},  //
                                         TestParams{65536}  //
                                         ));

TEST(IknpOtExtEdgeTest, Test) {
  // GIVEN
  const int kWorldSize = 2;
  auto contexts = link::test::SetupWorld(kWorldSize);

  BaseOtSendStore send_opts;
  BaseOtRecvStore recv_opts;
  std::tie(send_opts, recv_opts) = MakeBaseOptions(128);

  size_t kNumOt = 16;
  // WHEN THEN
  {
    // Mismatched receiver.
    std::vector<uint128_t> recv_out(kNumOt);
    std::vector<uint128_t> choices = crypto::RandVec<uint128_t>(kNumOt + 128);
    ASSERT_THROW(
        IknpOtExtRecv(contexts[1], send_opts, absl::MakeConstSpan(choices),
                      absl::MakeSpan(recv_out)),
        ::yacl::Exception);
  }
  {
    // Empty choice.
    std::vector<uint128_t> recv_out(kNumOt);
    std::vector<uint128_t> choices;
    ASSERT_THROW(
        IknpOtExtRecv(contexts[1], send_opts, absl::MakeConstSpan(choices),
                      absl::MakeSpan(recv_out)),
        ::yacl::Exception);
  }
  {
    // Empty send output.
    std::vector<std::array<uint128_t, 2>> send_out;
    ASSERT_THROW(
        IknpOtExtSend(contexts[1], recv_opts, absl::MakeSpan(send_out)),
        ::yacl::Exception);
  }
}

}  // namespace yacl
