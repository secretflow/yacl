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

#include "yacl/utils/spi/argument/util.h"

#include "gtest/gtest.h"

namespace yacl::util::test {

TEST(UtilTest, ToSnakeWorks) {
  EXPECT_EQ(ToSnakeCase("Hello"), "hello");
  EXPECT_EQ(ToSnakeCase("HelloWorld"), "hello_world");
  EXPECT_EQ(ToSnakeCase("hello"), "hello");
  EXPECT_EQ(ToSnakeCase("helloWorld"), "hello_world");
  EXPECT_EQ(ToSnakeCase("hello_world"), "hello_world");
  EXPECT_EQ(ToSnakeCase("hello-world"), "hello_world");
  EXPECT_EQ(ToSnakeCase("hello-worldHaha"), "hello_world_haha");

  EXPECT_EQ(ToSnakeCase(""), "");
  EXPECT_EQ(ToSnakeCase("T"), "t");
  EXPECT_EQ(ToSnakeCase("t"), "t");
  EXPECT_EQ(ToSnakeCase("Tesla"), "tesla");
  EXPECT_EQ(ToSnakeCase("Tesla3"), "tesla3");
  EXPECT_EQ(ToSnakeCase("TeslaModel3"), "tesla_model3");
  EXPECT_EQ(ToSnakeCase("teslaModel3"), "tesla_model3");
  EXPECT_EQ(ToSnakeCase("Tesla_Model3"), "tesla_model3");
  EXPECT_EQ(ToSnakeCase("tesla_Model3"), "tesla_model3");
  EXPECT_EQ(ToSnakeCase("Tesla_model3"), "tesla_model3");
  EXPECT_EQ(ToSnakeCase("tesla_model3"), "tesla_model3");
}

}  // namespace yacl::util::test
