// Copyright 2023 Ant Group Co., Ltd.
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

#include "yacl/utils/segment_tree.h"

#include <algorithm>
#include <iostream>
#include <iterator>
#include <random>
#include <vector>

#include "gtest/gtest.h"

namespace yacl::utils {

TEST(SegmentTreeTest, test) {
  std::vector<size_t> items(50);
  std::iota(items.begin(), items.end(), 1);
  std::random_device rd;
  std::mt19937 g(rd());

  std::shuffle(items.begin(), items.end(), g);

  SegmentTree<size_t> seg;

  for (auto item : items) {
    EXPECT_FALSE(seg.Contains(item));
    EXPECT_EQ(true, seg.Insert(item));
    EXPECT_TRUE(seg.Contains(item));
  }

  for (auto item : items) {
    EXPECT_EQ(false, seg.Insert(item));
  }

  EXPECT_EQ(1, seg.SegmentsCount());

  std::iota(items.begin(), items.end(), 101);

  for (auto item : items) {
    EXPECT_FALSE(seg.Contains(item));
    EXPECT_EQ(true, seg.Insert(item));
    EXPECT_TRUE(seg.Contains(item));
  }

  for (auto item : items) {
    EXPECT_EQ(false, seg.Insert(item));
  }

  EXPECT_EQ(2, seg.SegmentsCount());

  auto segs = seg.GetSegments();

  EXPECT_EQ(2, segs.size());

  EXPECT_EQ(segs[0].first, 1);
  EXPECT_EQ(segs[0].second, 51);

  EXPECT_EQ(segs[1].first, 101);
  EXPECT_EQ(segs[1].second, 151);

  std::iota(items.begin(), items.end(), 51);
  std::shuffle(items.begin(), items.end(), g);

  for (auto item : items) {
    EXPECT_FALSE(seg.Contains(item));
    EXPECT_EQ(true, seg.Insert(item));
    EXPECT_TRUE(seg.Contains(item));
  }

  for (auto item : items) {
    EXPECT_EQ(false, seg.Insert(item));
  }

  EXPECT_EQ(1, seg.SegmentsCount());

  segs = seg.GetSegments();

  EXPECT_EQ(1, segs.size());

  EXPECT_EQ(segs[0].first, 1);
  EXPECT_EQ(segs[0].second, 151);
}

}  // namespace yacl::utils
