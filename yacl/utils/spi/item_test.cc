// Copyright 2023 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "yacl/utils/spi/item.h"

#include "gtest/gtest.h"

namespace yacl::test {

TEST(ItemTest, RefRW) {
  std::vector<int> v = {1, 2, 3};

  Item item = Item::Ref(v);
  EXPECT_TRUE(item.IsArray());
  EXPECT_TRUE(item.IsView());
  EXPECT_FALSE(item.IsReadOnly());

  auto v_ref = item.AsSpan<int>();
  v_ref[1] = 10;
  ASSERT_EQ(v[1], 10);

  auto v_ref2 = item.AsSpan<const int>();
  ASSERT_EQ(typeid(v_ref2), typeid(absl::Span<const int>));
  v[2] = 30;
  EXPECT_EQ(v_ref2[2], 30);

  // sub span
  auto s_item = item.SubSpan<int>(1);
  EXPECT_TRUE(s_item.IsArray());
  EXPECT_TRUE(s_item.IsView());
  EXPECT_FALSE(s_item.IsReadOnly());

  auto s_ref = s_item.AsSpan<int>();
  s_ref[1] = 100;
  ASSERT_EQ(v[2], 100);

  auto s_ref2 = s_item.AsSpan<const int>();
  ASSERT_EQ(typeid(s_ref2), typeid(absl::Span<const int>));
  EXPECT_EQ(s_ref2.size(), 2);

  // sub const span
  auto c_item = item.SubSpan<const int>(1, 1000);
  EXPECT_TRUE(c_item.IsArray());
  EXPECT_TRUE(c_item.IsView());
  EXPECT_TRUE(c_item.IsReadOnly());

  // Exception: This is a read-only item, please use AsSpan<const T> instead
  EXPECT_ANY_THROW(c_item.AsSpan<int>());
  auto c_ref = c_item.AsSpan<const int>();
  ASSERT_EQ(typeid(c_ref), typeid(absl::Span<const int>));
  EXPECT_EQ(s_ref2.size(), 2);
  v[1] = 666;
  EXPECT_EQ(c_ref[0], 666);
}

TEST(ItemTest, RefRO) {
  const std::vector<int> v = {1, 2, 3};
  Item item = Item::Ref(v);
  EXPECT_TRUE(item.IsArray());
  EXPECT_TRUE(item.IsView());
  EXPECT_TRUE(item.IsReadOnly());

  // Exception: This is a read-only item, please use AsSpan<const T> instead
  EXPECT_ANY_THROW(item.AsSpan<int>());
  auto v_ref = item.AsSpan<const int>();
  ASSERT_EQ(typeid(v_ref), typeid(absl::Span<const int>));
  EXPECT_EQ(v_ref[0], 1);

  const Item &item2 = item;
  auto v_ref2 = item2.AsSpan<int>();
  ASSERT_EQ(typeid(v_ref2), typeid(absl::Span<const int>));
  EXPECT_EQ(v_ref2[2], 3);

  // sub const span
  auto s_item = item.SubSpan<int>(1);
  EXPECT_TRUE(s_item.IsArray());
  EXPECT_TRUE(s_item.IsView());
  EXPECT_TRUE(s_item.IsReadOnly());
  // Exception: This is a read-only item, please use AsSpan<const T> instead
  EXPECT_ANY_THROW(s_item.AsSpan<int>());
  auto s_ref = s_item.AsSpan<const int>();
  EXPECT_EQ(s_ref[0], 2);

  const auto s_item2 = item2.SubSpan<int>(2);
  EXPECT_TRUE(s_item2.IsArray());
  EXPECT_TRUE(s_item2.IsView());
  EXPECT_TRUE(s_item2.IsReadOnly());
  auto s_ref2 = s_item2.AsSpan<int>();
  EXPECT_EQ(s_ref2[0], 3);
}

}  // namespace yacl::test
