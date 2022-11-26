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

#include "yacl/link/algorithm/gather.h"

#include <future>

#include "gtest/gtest.h"

#include "yacl/link/test_util.h"

namespace yacl::link::test {

struct TestParams {
  size_t world_size;
};

class GatherTest : public ::testing::TestWithParam<TestParams> {};

TEST_P(GatherTest, Works) {
  const size_t world_size = GetParam().world_size;
  auto contexts = SetupWorld(world_size);

  auto proc = [&](const std::shared_ptr<Context>& ctx) {
    for (size_t round = 0; round < world_size; round++) {
      const auto input = MakeRoundData(ctx->Rank(), round);
      // each round take a different party as root.
      const size_t root = round;
      std::vector<Buffer> output;
      if (round % 2) {
        output = Gather(ctx, std::move(input), root, "test_tag");
      } else {
        output = Gather(ctx, input, root, "test_tag");
      }

      // verify
      if (ctx->Rank() == root) {
        EXPECT_EQ(output.size(), world_size);
        for (size_t cc = 0; cc < world_size; cc++) {
          EXPECT_EQ(output[cc], yacl::Buffer(MakeRoundData(cc, round)));
        }
      } else {
        EXPECT_TRUE(output.empty());
      }
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

TEST_P(GatherTest, VectorWorks) {
  const size_t n_rounds = GetParam().world_size;
  const size_t world_size = GetParam().world_size;
  auto contexts = SetupWorld(world_size);

  auto proc = [&](const std::shared_ptr<Context>& ctx) {
    for (size_t round = 0; round < n_rounds; round++) {
      for (int size : {0, 1, 5}) {
        std::vector<std::string> inputs;
        for (int i = 0; i < size; ++i) {
          inputs.emplace_back(std::to_string(i + round + ctx->Rank()));
        }
        // each round take a different party as root.
        const size_t root = round;
        std::vector<std::vector<Buffer>> result =
            Gather(ctx, {inputs.begin(), inputs.end()}, root, "test_tag");

        EXPECT_EQ(result.size(), size);
        for (int i = 0; i < size; ++i) {
          if (ctx->Rank() == root) {
            EXPECT_EQ(result[i].size(), world_size);
            for (size_t rank = 0; rank < world_size; rank++) {
              auto s = std::to_string(i + round + rank);
              EXPECT_EQ(
                  std::memcmp(result[i][rank].data<char>(), s.data(), s.size()),
                  0);
            }
          } else {
            EXPECT_TRUE(result[i].empty());
          }
        }
      }
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

INSTANTIATE_TEST_SUITE_P(Works_Instances, GatherTest,
                         testing::Values(TestParams{2},  //
                                         TestParams{3},  //
                                         TestParams{9}   //
                                         ));

}  // namespace yacl::link::test
