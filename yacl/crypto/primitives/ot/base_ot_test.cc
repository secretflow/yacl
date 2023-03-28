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

#include "yacl/crypto/primitives/ot/base_ot.h"

#include <future>
#include <thread>

#include "fmt/format.h"
#include "gtest/gtest.h"

#include "yacl/base/exception.h"
#include "yacl/crypto/utils/rand.h"
#include "yacl/link/test_util.h"

namespace yacl::crypto {

struct TestParams {
  unsigned num_ot;
};

class BaseOtTest : public ::testing::TestWithParam<TestParams> {};

TEST_P(BaseOtTest, Works) {
  // GIVEN
  const int kWorldSize = 2;
  auto contexts = link::test::SetupWorld(kWorldSize);

  std::vector<std::array<Block, 2>> send_blocks;
  std::vector<Block> recv_blocks;

  auto params = GetParam();
  send_blocks.resize(params.num_ot);
  recv_blocks.resize(params.num_ot);

  // WHEN
  auto choices = RandBits<dynamic_bitset<uint128_t>>(params.num_ot);
  std::future<void> sender =
      std::async([&] { BaseOtSend(contexts[0], absl::MakeSpan(send_blocks)); });
  std::future<void> receiver = std::async(
      [&] { BaseOtRecv(contexts[1], choices, absl::MakeSpan(recv_blocks)); });
  sender.get();
  receiver.get();

  // THEN
  for (unsigned i = 0; i < params.num_ot; ++i) {
    unsigned idx = choices[i] ? 1 : 0;
    EXPECT_EQ(send_blocks[i][idx], recv_blocks[i]);
    EXPECT_NE(recv_blocks[i], 0);
    EXPECT_NE(send_blocks[i][0], 0);
    EXPECT_NE(send_blocks[i][1], 0);
  }
}

TEST_P(BaseOtTest, OtStoreWorks) {
  // GIVEN
  const int kWorldSize = 2;
  auto contexts = link::test::SetupWorld(kWorldSize);

  auto params = GetParam();

  // WHEN
  auto choices = RandBits<dynamic_bitset<uint128_t>>(params.num_ot);
  auto sender =
      std::async([&] { return BaseOtSend(contexts[0], params.num_ot); });
  auto receiver = std::async(
      [&] { return BaseOtRecv(contexts[1], choices, params.num_ot); });
  auto send_blocks = sender.get();
  auto recv_blocks = receiver.get();

  // THEN
  for (unsigned i = 0; i < params.num_ot; ++i) {
    unsigned idx = choices[i] ? 1 : 0;
    EXPECT_EQ(send_blocks->GetBlock(i, idx), recv_blocks->GetBlock(i));
  }
}

INSTANTIATE_TEST_SUITE_P(Works_Instances, BaseOtTest,
                         testing::Values(TestParams{1},    //
                                         TestParams{128},  //
                                         TestParams{127},  //
                                         TestParams{233}   //
                                         ));

TEST(BaseOtEdgeTest, Test) {
  // GIVEN
  std::vector<std::array<Block, 2>> send_blocks;
  std::vector<Block> recv_blocks;
  dynamic_bitset<uint128_t> choices;

  auto contexts = link::test::SetupWorld(2);

  // WHEN THEN
  ASSERT_THROW(BaseOtRecv(contexts[0], choices, absl::MakeSpan(recv_blocks)),
               ::yacl::Exception);
  ASSERT_THROW(BaseOtSend(contexts[1], absl::MakeSpan(send_blocks)),
               ::yacl::Exception);
}

}  // namespace yacl::crypto
