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


#include "yasl/mpctools/ot/punctured_rand_ot.h"

#include <future>
#include <thread>

#include "fmt/format.h"
#include "gtest/gtest.h"

#include "yasl/base/exception.h"
#include "yasl/crypto/utils.h"
#include "yasl/link/test_util.h"
#include "yasl/mpctools/ot/options.h"

namespace yasl::crypto {

uint32_t GetRandValue(size_t n) {
  std::random_device rd;
  PseudoRandomGenerator<uint32_t> gen(rd());
  return gen() % n;
}

// mock a lot of 1-2 OT instances ...
std::pair<OTSendOptions, OTRecvOptions> MakeOTOptions(size_t num) {
  BaseSendOptions send_opts;
  BaseRecvOptions recv_opts;
  recv_opts.choices = CreateRandomChoices(num);
  std::random_device rd;
  PseudoRandomGenerator<uint64_t> gen(rd());
  for (size_t i = 0; i < num; ++i) {
    send_opts.blocks.push_back({gen(), gen()});
    recv_opts.blocks.push_back(send_opts.blocks[i][recv_opts.choices[i]]);
  }
  return {std::move(send_opts), std::move(recv_opts)};
}

struct TestParams {
  unsigned n;
};

class RotParamTest : public ::testing::TestWithParam<TestParams> {};

TEST_P(RotParamTest, Works) {
  uint32_t n = GetParam().n;
  uint64_t master_seed = 0;
  uint32_t choice_value = GetRandValue(n);

  // mock many base OTs
  BaseSendOptions send_opts;
  BaseRecvOptions recv_opts;
  std::tie(send_opts, recv_opts) = MakeOTOptions(log2(n));

  std::vector<PuncturedOTSeed> entire_seeds(n);
  std::vector<PuncturedOTSeed> punctured_seeds(n - 1);

  auto contexts = link::test::SetupWorld(2);
  std::future<void> sender = std::async([&] {
    PuncturedROTRecv(contexts[0], recv_opts, n, choice_value,
                     absl::MakeSpan(punctured_seeds));
  });
  std::future<void> receiver = std::async([&] {
    PuncturedROTSend(contexts[1], send_opts, n, master_seed,
                     absl::MakeSpan(entire_seeds));
  });
  sender.get();
  receiver.get();

  EXPECT_EQ(entire_seeds.size(), n);
  EXPECT_EQ(punctured_seeds.size(), n - 1);

  bool triger = false;
  for (uint32_t i = 0; i < n - 1; i++) {
    if (i == choice_value) triger = true;
    if (triger == false)
      EXPECT_EQ(entire_seeds.at(i), punctured_seeds.at(i)) << i;
    else
      EXPECT_EQ(entire_seeds.at(i + 1), punctured_seeds.at(i)) << i;
  }
}

INSTANTIATE_TEST_SUITE_P(Works_Instances, RotParamTest,
                         testing::Values(TestParams{4},        //
                                         TestParams{1 << 10},  //
                                         TestParams{1 << 15}   //
                                         ));

TEST(RotFuncTest, Test) {
  uint32_t n = 4;
  uint64_t master_seed = 0;
  uint32_t choice_value = GetRandValue(n);

  // mock many base OTs
  BaseSendOptions send_opts;
  BaseRecvOptions recv_opts;
  std::tie(send_opts, recv_opts) = MakeOTOptions(log2(n));

  std::vector<PuncturedOTSeed> entire_seeds(n);
  std::vector<PuncturedOTSeed> punctured_seeds(n - 1);

  auto contexts = link::test::SetupWorld(2);
  std::future<void> sender = std::async([&] {
    PuncturedROTRecv(contexts[0], recv_opts, n, choice_value,
                     absl::MakeSpan(punctured_seeds));
  });
  std::future<void> receiver = std::async([&] {
    PuncturedROTSend(contexts[1], send_opts, n, master_seed,
                     absl::MakeSpan(entire_seeds));
  });
  sender.get();
  receiver.get();

  EXPECT_EQ(entire_seeds.size(), n);
  EXPECT_EQ(punctured_seeds.size(), n - 1);

  bool triger = false;
  for (uint32_t i = 0; i < n - 1; i++) {
    if (i == choice_value) triger = true;
    if (triger == false)
      EXPECT_EQ(entire_seeds.at(i), punctured_seeds.at(i)) << i;
    else
      EXPECT_EQ(entire_seeds.at(i + 1), punctured_seeds.at(i)) << i;
  }
}

}  // namespace yasl::crypto