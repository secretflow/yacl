// Copyright 2019 Ant Group Co., Ltd.
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

#include "yacl/link/algorithm/broadcast.h"

#include <future>

#include "gtest/gtest.h"

#include "yacl/link/test_util.h"

namespace yacl::link::test {

struct TestParams {
  size_t world_size;
};

class BroadcastTest : public ::testing::TestWithParam<TestParams> {};

TEST_P(BroadcastTest, Works) {
  const size_t world_size = GetParam().world_size;
  auto contexts = SetupWorld(world_size);

  auto proc = [&](const std::shared_ptr<Context>& ctx) {
    for (size_t round = 0; round < world_size; round++) {
      // each round take a different party as root.
      auto root = round;
      auto input = ctx->Rank() == root
                       ? yacl::Buffer(MakeRoundData(root, round))
                       : Buffer();

      auto output = Broadcast(ctx, input, root, "test");

      EXPECT_EQ(output, yacl::Buffer(MakeRoundData(root, round)));
    }
  };

  std::vector<std::future<void>> jobs(world_size);
  for (size_t rank = 0; rank < world_size; rank++) {
    jobs[rank] = std::async(proc, contexts[rank]);
  }

  for (size_t rank = 0; rank < world_size; rank++) {
    jobs[rank].get();
  }
}

INSTANTIATE_TEST_SUITE_P(Works_Instances, BroadcastTest,
                         testing::Values(TestParams{2},  //
                                         TestParams{3},  //
                                         TestParams{7},  //
                                         TestParams{9},  //
                                         TestParams{32}  //
                                         ));

}  // namespace yacl::link::test
