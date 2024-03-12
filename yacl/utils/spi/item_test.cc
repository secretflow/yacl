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
  EXPECT_EQ(item.Size<int>(), 3);

  auto v_ref = item.AsSpan<int>();
  v_ref[1] = 10;
  ASSERT_EQ(v[1], 10);

  auto v_ref2 = item.AsSpan<const int>();
  ASSERT_EQ(typeid(v_ref2), typeid(absl::Span<const int>));
  v[2] = 30;
  EXPECT_EQ(v_ref2[2], 30);

  // sub span
  auto s_item = item.SubItem<int>(1);
  EXPECT_TRUE(s_item.IsArray());
  EXPECT_TRUE(s_item.IsView());
  EXPECT_FALSE(s_item.IsReadOnly());
  EXPECT_EQ(s_item.Size<int>(), 2);

  auto s_ref = s_item.AsSpan<int>();
  s_ref[1] = 100;
  ASSERT_EQ(v[2], 100);

  auto s_ref2 = s_item.AsSpan<const int>();
  ASSERT_EQ(typeid(s_ref2), typeid(absl::Span<const int>));
  EXPECT_EQ(s_ref2.size(), 2);

  // sub const span
  auto c_item = item.SubItem<const int>(1, 1000);
  EXPECT_TRUE(c_item.IsArray());
  EXPECT_TRUE(c_item.IsView());
  EXPECT_TRUE(c_item.IsReadOnly());
  EXPECT_EQ(c_item.Size<int>(), 2);

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
  ASSERT_TRUE(is_container_v<decltype(absl::MakeSpan(v))>);

  Item item = Item::Ref(v);
  EXPECT_TRUE(item.IsArray());
  EXPECT_TRUE(item.IsView());
  EXPECT_TRUE(item.IsReadOnly());
  EXPECT_EQ(item.Size<int>(), 3);

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
  auto s_item = item.SubItem<int>(1);
  EXPECT_TRUE(s_item.IsArray());
  EXPECT_TRUE(s_item.IsView());
  EXPECT_TRUE(s_item.IsReadOnly());
  EXPECT_EQ(s_item.Size<int>(), 2);
  // Exception: This is a read-only item, please use AsSpan<const T> instead
  EXPECT_ANY_THROW(s_item.AsSpan<int>());
  auto s_ref = s_item.AsSpan<const int>();
  EXPECT_EQ(s_ref[0], 2);

  const auto s_item2 = item2.SubItem<int>(2);
  EXPECT_TRUE(s_item2.IsArray());
  EXPECT_TRUE(s_item2.IsView());
  EXPECT_TRUE(s_item2.IsReadOnly());
  EXPECT_EQ(s_item2.Size<int>(), 1);
  auto s_ref2 = s_item2.AsSpan<int>();
  EXPECT_EQ(s_ref2[0], 3);
}

TEST(ItemTest, RefPtr) {
  int arr[] = {1, 2, 3};
  auto item = Item::Ref(arr, 3);
  EXPECT_TRUE(item.IsArray());
  EXPECT_TRUE(item.IsView());
  EXPECT_FALSE(item.IsReadOnly());
  EXPECT_EQ(item.Size<int>(), 3);

  const int arr2[] = {1, 2, 3};
  item = Item::Ref(arr2, 3);
  EXPECT_TRUE(item.IsArray());
  EXPECT_TRUE(item.IsView());
  EXPECT_TRUE(item.IsReadOnly());
  EXPECT_EQ(item.Size<int>(), 3);
}

TEST(ItemTest, ResizeAndSpan) {
  // Vector<T> case
  auto item = Item::Take(std::vector<int>());
  EXPECT_EQ(item.AsSpan<int>().size(), 0);
  EXPECT_EQ(item.Size<int>(), 0);

  auto sp = item.ResizeAndSpan<int>(100);
  EXPECT_EQ(sp.size(), 100);
  EXPECT_EQ(item.Size<int>(), 100);

  sp = item.ResizeAndSpan<int>(50);
  EXPECT_EQ(sp.size(), 50);
  EXPECT_EQ(item.Size<int>(), 100);

  sp[29] = 456;
  EXPECT_EQ(item.SubItem<int>(29, 20).AsSpan<int>()[0], 456);

  // ... with type change
  auto sp2 = item.ResizeAndSpan<std::string>(0);
  EXPECT_EQ(sp2.size(), 0);
  EXPECT_EQ(item.Size<std::string>(), 0);

  // Single T case
  item = (int)3;
  EXPECT_FALSE(item.IsArray());
  sp = item.ResizeAndSpan<int>(40);
  EXPECT_TRUE(item.IsArray());
  EXPECT_FALSE(item.IsView());
  EXPECT_FALSE(item.IsReadOnly());
  EXPECT_EQ(sp.size(), 40);
  EXPECT_EQ(item.Size<int>(), 40);
  EXPECT_EQ(sp[0], 3);

  // ... with type change
  item = "hello";
  auto sp3 = item.ResizeAndSpan<double>(1);
  EXPECT_EQ(sp3.size(), 1);
  EXPECT_EQ(item.Size<double>(), 1);

  // Span<T> case
  std::vector<int> vec = {1, 2, 3};
  item = Item::Ref(vec);
  EXPECT_TRUE(item.IsArray());
  EXPECT_TRUE(item.IsView());
  sp = item.ResizeAndSpan<int>(2);
  EXPECT_EQ(sp.size(), 2);
  EXPECT_EQ(item.Size<int>(), 3);
  sp[1] = 456;
  EXPECT_EQ(vec[1], 456);
  sp = item.ResizeAndSpan<int>(3);
  EXPECT_EQ(sp.size(), 3);
  EXPECT_EQ(item.Size<int>(), 3);
  EXPECT_EQ(sp[2], 3);
  // cannot resize a span
  EXPECT_ANY_THROW(item.ResizeAndSpan<int>(4));
  // cannot change type
  EXPECT_ANY_THROW(item.ResizeAndSpan<double>(1));
}

class DummyItem : public Item {
 public:
  using Item::Item;

  // make function public
  template <int slot, int len = 1>
  constexpr void ProxySetSlot(uint8_t value) {
    Item::SetSlot<slot, len>(value);
  }

  template <int slot, int len = 1>
  constexpr uint8_t ProxyGetSlot() const {
    return Item::GetSlot<slot, len>();
  }
};

TEST(ItemTest, SlotWorks) {
  DummyItem item = 123456;

  item.ProxySetSlot<6>(1);
  EXPECT_EQ(item.ProxyGetSlot<6>(), 1);
  item.ProxySetSlot<6>(0);
  EXPECT_EQ(item.ProxyGetSlot<6>(), 0);

  item.ProxySetSlot<3>(1);
  item.ProxySetSlot<5, 2>(0b11);  // slot 5, 6 = 1, 1
  EXPECT_EQ((item.ProxyGetSlot<5, 2>()), 0b11);
  EXPECT_EQ(item.ProxyGetSlot<3>(), 1);
  EXPECT_EQ(item.ProxyGetSlot<4>(), 0);
  EXPECT_EQ(item.ProxyGetSlot<5>(), 1);
  EXPECT_EQ(item.ProxyGetSlot<6>(), 1);
  EXPECT_EQ(item.ProxyGetSlot<4>(), 0);

  item.ProxySetSlot<5, 2>(0b01);  // slot 5, 6 = 1, 0
  EXPECT_EQ((item.ProxyGetSlot<5, 2>()), 0b01);
  EXPECT_EQ(item.ProxyGetSlot<3>(), 1);
  EXPECT_EQ(item.ProxyGetSlot<4>(), 0);
  EXPECT_EQ(item.ProxyGetSlot<5>(), 1);
  EXPECT_EQ(item.ProxyGetSlot<6>(), 0);
  EXPECT_EQ(item.ProxyGetSlot<4>(), 0);

  item.ProxySetSlot<5, 3>(0);
  EXPECT_EQ((item.ProxyGetSlot<5, 2>()), 0);
  EXPECT_EQ((item.ProxyGetSlot<5, 3>()), 0);

  EXPECT_FALSE(item.IsArray());
  EXPECT_FALSE(item.IsView());
  EXPECT_FALSE(item.IsReadOnly());
}

TEST(ItemTest, ItemInContainer) {
  std::vector<Item> items;
  EXPECT_NO_THROW(items.emplace_back(123));
  EXPECT_NO_THROW(items.emplace_back("haha"));
  EXPECT_NO_THROW(items.emplace_back(true));

  EXPECT_NO_THROW(items.push_back(456ull));
  EXPECT_NO_THROW(
      items.push_back(Item::Take(std::vector{"h", "e", "l", "l", "o"})));
}

}  // namespace yacl::test
