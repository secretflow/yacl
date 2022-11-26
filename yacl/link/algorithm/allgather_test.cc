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

#include "yacl/link/algorithm/allgather.h"

#include <future>

#include "gtest/gtest.h"

#include "yacl/link/test_util.h"

namespace yacl::link::test {

struct TestParams {
  size_t world_size;
  size_t n_rounds;
};

class AllGatherTest : public ::testing::TestWithParam<TestParams> {};

TEST_P(AllGatherTest, Works) {
  const size_t n_rounds = GetParam().n_rounds;
  const size_t world_size = GetParam().world_size;
  auto contexts = SetupWorld(world_size);

  auto proc = [&](const std::shared_ptr<Context>& ctx) {
    for (size_t round = 0; round < n_rounds; round++) {
      std::vector<Buffer> result =
          AllGather(ctx, MakeRoundData(ctx->Rank(), round), "test");

      EXPECT_EQ(result.size(), world_size);
      for (size_t rank = 0; rank < world_size; rank++) {
        EXPECT_EQ(result[rank], yacl::Buffer(MakeRoundData(rank, round)));
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

TEST_P(AllGatherTest, VectorWorks) {
  const size_t n_rounds = GetParam().n_rounds;
  const size_t world_size = GetParam().world_size;
  auto contexts = SetupWorld(world_size);

  auto proc = [&](const std::shared_ptr<Context>& ctx) {
    for (size_t round = 0; round < n_rounds; round++) {
      for (int size : {0, 1, 5}) {
        std::vector<std::string> inputs;
        for (int i = 0; i < size; ++i) {
          inputs.emplace_back(std::to_string(i + round + ctx->Rank()));
        }
        std::vector<std::vector<Buffer>> result =
            AllGather(ctx, {inputs.begin(), inputs.end()}, "test");

        EXPECT_EQ(result.size(), size);
        for (int i = 0; i < size; ++i) {
          EXPECT_EQ(result[i].size(), world_size);
          for (size_t rank = 0; rank < world_size; rank++) {
            auto s = std::to_string(i + round + rank);
            EXPECT_EQ(
                std::memcmp(result[i][rank].data<char>(), s.data(), s.size()),
                0);
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

INSTANTIATE_TEST_SUITE_P(Works_Instances, AllGatherTest,
                         testing::Values(TestParams{2, 20},  //
                                         TestParams{3, 20},  //
                                         TestParams{9, 20}   //
                                         ));

}  // namespace yacl::link::test
