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

#include "yacl/link/algorithm/barrier.h"

#include <chrono>
#include <future>
#include <random>
#include <thread>

#include "gtest/gtest.h"

#include "yacl/link/test_util.h"

namespace yacl::link::test {

struct TestParams {
  size_t world_size;
  size_t n_rounds;
};

class BarrierTest : public ::testing::TestWithParam<TestParams> {};

TEST_P(BarrierTest, Works) {
  const size_t n_rounds = GetParam().n_rounds;
  const size_t world_size = GetParam().world_size;
  auto contexts = SetupWorld(world_size);

  std::mt19937_64 eng{std::random_device{}()};
  std::uniform_int_distribution<> dist{1, 50};

  std::vector<size_t> cnts(world_size, 0);
  auto proc = [&](const std::shared_ptr<Context>& ctx) {
    for (size_t round = 0; round < n_rounds; round++) {
      // random sleep for different members.
      std::this_thread::sleep_for(std::chrono::milliseconds{dist(eng)});

      cnts[ctx->Rank()]++;

      Barrier(ctx, "test_tag");
      EXPECT_TRUE(std::equal(cnts.begin() + 1, cnts.end(), cnts.begin()));
      Barrier(ctx, "test_tag1");
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

INSTANTIATE_TEST_SUITE_P(Works_Instances, BarrierTest,
                         testing::Values(TestParams{2, 20},  //
                                         TestParams{3, 20},  //
                                         TestParams{9, 20}   //
                                         ));

}  // namespace yacl::link::test
