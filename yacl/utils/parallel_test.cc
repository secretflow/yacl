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

#include "yacl/utils/parallel.h"

#include <numeric>

#include "gtest/gtest.h"

namespace yacl {

struct Param {
  int num_threads;
  int data_size;
  int grain_size;
};

class ParallelTest : public testing::TestWithParam<Param> {};

TEST_P(ParallelTest, ParallelForTest) {
  auto param = GetParam();

  init_num_threads();
  set_num_threads(param.num_threads);

  std::vector<int> data(param.data_size);
  std::iota(data.begin(), data.end(), 0);

  parallel_for(0, data.size(), param.grain_size,
               [&data](int64_t beg, int64_t end) {
                 for (int64_t i = beg; i < end; ++i) {
                   data[i] *= 2;
                 }
               });

  for (size_t i = 0; i < data.size(); ++i) {
    ASSERT_EQ(i * 2, data[i]);
  }
}

TEST(ParallelTest, ParallelWithExceptionTest) {
  init_num_threads();
  set_num_threads(4);

  EXPECT_THROW(
      parallel_for(0, 1000, 1,
                   [](int64_t, int64_t) { throw RuntimeError("surprise"); }),
      RuntimeError);
}

TEST_P(ParallelTest, ParallelReduceTest) {
  auto param = GetParam();

  init_num_threads();
  set_num_threads(param.num_threads);

  std::vector<int> data(param.data_size);
  std::iota(data.begin(), data.end(), 0);
  int expect_sum = std::accumulate(data.begin(), data.end(), 0);

  int total_sum = parallel_reduce<int>(
      0, data.size(), param.grain_size,
      [&data](int64_t beg, int64_t end) {
        int partial_sum = data[beg];
        for (int64_t i = beg + 1; i < end; ++i) {
          partial_sum += data[i];
        }
        return partial_sum;
      },
      [](int a, int b) { return a + b; });

  ASSERT_EQ(expect_sum, total_sum);
}

INSTANTIATE_TEST_SUITE_P(ParallelTestSuit, ParallelTest,
                         testing::Values(Param{4, 123, 10}, Param{4, 123, 50},
                                         Param{4, 123, 200}));

}  // namespace yacl
