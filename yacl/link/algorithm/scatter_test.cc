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

#include "yacl/link/algorithm/scatter.h"

#include <future>

#include "gtest/gtest.h"

#include "yacl/base/exception.h"
#include "yacl/link/test_util.h"

namespace yacl::link::test {

struct TestParams {
  size_t world_size;
};

class ScatterTest : public ::testing::TestWithParam<TestParams> {};

TEST_P(ScatterTest, Works) {
  const size_t world_size = GetParam().world_size;
  auto contexts = SetupWorld(world_size);

  auto proc = [&](const std::shared_ptr<Context>& ctx) {
    for (size_t round = 0; round < world_size; round++) {
      // each round take a different party as root.
      size_t root = round;
      std::vector<std::string> inputs;
      if (ctx->Rank() == root) {
        for (size_t rank = 0; rank < world_size; rank++) {
          inputs.push_back(MakeRoundData(rank, round));
        }
      }

      auto data =
          Scatter(ctx, {inputs.begin(), inputs.end()}, root, "test_tag");

      // verify
      EXPECT_EQ(data, yacl::Buffer(MakeRoundData(ctx->Rank(), round)));
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

INSTANTIATE_TEST_SUITE_P(Works_Instances, ScatterTest,
                         testing::Values(TestParams{2},  //
                                         TestParams{3},  //
                                         TestParams{9}   //
                                         ));

TEST(ScatterFailTest, ThrowExceptionIfSizeNotMatch) {
  const size_t world_size = 2;
  auto contexts = SetupWorld("SizeMissMatch", world_size);

  size_t wrong_world_size = world_size + 1;
  std::vector<std::string> inputs;
  inputs.resize(wrong_world_size);
  size_t root = 0;
  EXPECT_THROW(
      Scatter(contexts[root], {inputs.begin(), inputs.end()}, root, "test_tag"),
      ::yacl::EnforceNotMet);
}

}  // namespace yacl::link::test
