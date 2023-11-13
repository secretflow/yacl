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

#include "yacl/io/msgpack/buffer.h"

#include "gtest/gtest.h"

namespace yacl::io::test {

TEST(TestStreamBuffer, SimpleWorks) {
  Buffer buffer(3);
  StreamBuffer sbuf(&buffer);

  EXPECT_EQ(sbuf.WrittenSize(), 0);

  std::string abc = "abc";
  sbuf.write(std::string_view(abc));
  sbuf.write("d", 1);

  EXPECT_EQ(std::string(buffer.data<char>(), buffer.size()), "abcd");
}

}  // namespace yacl::io::test
