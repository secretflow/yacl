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

#include <cstdint>
#include <numeric>

#include "gtest/gtest.h"

#include "yacl/base/exception.h"

namespace yacl {

TEST(ParallelTest, ParallelForTest) {
  std::vector<int> data(200);
  std::iota(data.begin(), data.end(), 0);

  parallel_for(0, data.size(), [&data](int64_t beg, int64_t end) {
    for (int64_t i = beg; i < end; ++i) {
      data[i] *= 2;
    }
  });

  for (size_t i = 0; i < data.size(); ++i) {
    ASSERT_EQ(i * 2, data[i]);
  }
}

TEST(ParallelTest, ParallelForBatchedTest) {
  std::vector<int> data(200);
  std::iota(data.begin(), data.end(), 0);

  parallel_for(0, data.size(), 50, [&data](int64_t begin, int64_t end) {
    for (int64_t i = begin; i < end; ++i) {
      data[i] *= 2;
    }
  });

  for (size_t i = 0; i < data.size(); ++i) {
    ASSERT_EQ(i * 2, data[i]);
  }
}

TEST(ParallelTest, ParallelForBatchedWithTrailingTest) {
  std::vector<int> data(210);
  std::iota(data.begin(), data.end(), 0);

  parallel_for(0, data.size(), 50, [&data](int64_t begin, int64_t end) {
    for (int64_t i = begin; i < end; ++i) {
      data[i] *= 2;
    }
  });

  for (size_t i = 0; i < data.size(); ++i) {
    ASSERT_EQ(i * 2, data[i]);
  }
}

TEST(ParallelTest, ParallelWithExceptionTest) {
  EXPECT_THROW(
      parallel_for(0, 1000,
                   [](int64_t, int64_t) { throw RuntimeError("surprise"); }),
      RuntimeError);
  EXPECT_THROW(
      parallel_for(0, 1000, 1,
                   [](int64_t, int64_t) { throw RuntimeError("surprise"); }),
      RuntimeError);
}

TEST(ParallelTest, ParallelReduceTest) {
  std::vector<int> data(500);
  std::iota(data.begin(), data.end(), 0);
  int expect_sum = std::accumulate(data.begin(), data.end(), 0);
  int total_sum = parallel_reduce<int>(
      0, data.size(), 1,
      [&data](int64_t beg, int64_t end) -> int {
        int partial_sum = data[beg];
        for (int64_t i = beg + 1; i < end; ++i) {
          partial_sum += data[i];
        }
        return partial_sum;
      },
      [](int a, int b) { return a + b; });
  ASSERT_EQ(expect_sum, total_sum);
}

}  // namespace yacl
