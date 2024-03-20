// Copyright 2024 Ant Group Co., Ltd.
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

#include "yacl/utils/serializer.h"

#include "gtest/gtest.h"

#include "yacl/base/int128.h"
#include "yacl/utils/serializer_adapter.h"

namespace yacl::test {

TEST(SerializerTest, SingleWorks) {
  int64_t v1 = -12345;
  int64_t f1;

  // ser/deser single
  auto buf = SerializeVars(v1);
  // DeserializeVars<int64_t> directly returns int64_t
  ASSERT_EQ(DeserializeVars<int64_t>(buf), v1);

  ASSERT_EQ(buf.size(), SerializeVarsTo(nullptr, 0, v1));
  ASSERT_EQ(buf.size(), SerializeVarsTo(buf.data<uint8_t>(), buf.size(), v1));
  DeserializeVarsTo(buf, &f1);
  ASSERT_EQ(v1, f1);
}

TEST(SerializerTest, MultiWorks) {
  int64_t v1 = -12345;
  bool v2 = true;
  std::string v3 = "hello";
  double v4 = 1.2;
  int64_t v5 = 987;  // test type is duplicate with v1

  auto buf = SerializeVars(v1, v2, v3, v4, v5);
  auto [f1, f2, f3, f4, f5] =
      DeserializeVars<int64_t, bool, std::string, double, int64_t>(buf);
  EXPECT_EQ(v1, f1);
  EXPECT_EQ(v2, f2);
  EXPECT_EQ(v3, f3);
  EXPECT_EQ(v4, f4);
  EXPECT_EQ(v5, f5);

  ASSERT_EQ(buf.size(), SerializeVarsTo(nullptr, 0, v1, v2, v3, v4, v5));
  ASSERT_EQ(buf.size(), SerializeVarsTo(buf.data<uint8_t>(), buf.size(), v1, v2,
                                        v3, v4, v5));
  std::tie(f1, f2, f3, f4, f5) = std::make_tuple(0, false, "", .0, 0);
  DeserializeVarsTo(buf, &f1, &f2, &f3, &f4, &f5);
  EXPECT_EQ(v1, f1);
  EXPECT_EQ(v2, f2);
  EXPECT_EQ(v3, f3);
  EXPECT_EQ(v4, f4);
}

TEST(SerializerTest, Int128) {
  int128_t v1 = yacl::MakeInt128(INT64_MAX, INT64_MAX);
  auto buf = SerializeVars(v1);
  EXPECT_EQ(DeserializeVars<int128_t>(buf), v1);

  uint128_t v2 = yacl::MakeUint128(INT64_MAX, 123);
  buf = SerializeVars(v2);
  EXPECT_EQ(DeserializeVars<uint128_t>(buf), v2);
}

TEST(SerializerTest, Buffer) {
  // test serializes raw buffer
  yacl::Buffer hello(std::string("hello"));

  auto buf = SerializeVars(hello, hello);
  auto [f1, f2] = DeserializeVars<yacl::Buffer, yacl::ByteContainerView>(buf);
  EXPECT_EQ(std::string(f1.data<char>(), f1.size()), "hello");
  EXPECT_EQ((std::string_view)f2, "hello");

  ByteContainerView view1, view2;
  DeserializeVarsTo(buf, &view1, &view2);
  EXPECT_EQ(
      std::string(reinterpret_cast<const char *>(view1.data()), view1.size()),
      "hello");
  EXPECT_EQ(
      std::string(reinterpret_cast<const char *>(view2.data()), view2.size()),
      "hello");
}

}  // namespace yacl::test
