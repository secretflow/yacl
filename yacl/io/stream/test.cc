// Copyright 2022 Ant Group Co., Ltd.
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

#include <cstdint>
#include <ctime>
#include <filesystem>

#include "gtest/gtest.h"

#include "yacl/base/exception.h"
#include "yacl/io/stream/file_io.h"
#include "yacl/io/stream/mem_io.h"

namespace yacl::io {

struct TestParams {
  const char* data;
  size_t while_count;
  const char* last_line;
};

class IOTest : public ::testing::Test,
               public ::testing::WithParamInterface<TestParams> {};

INSTANTIATE_TEST_SUITE_P(IOTest, IOTest,
                         testing::Values(TestParams{"aaa\nbbb\nccc", 3, "ccc"},
                                         TestParams{"aaa\nbbb\nccc\n", 3, ""}));

TEST_P(IOTest, MemIO) {
  auto param = GetParam();

  {
    std::string input(param.data);
    std::unique_ptr<InputStream> in(new MemInputStream(input));
    EXPECT_EQ(input.size(), in->GetLength());
    int count = 0;
    std::string line;
    EXPECT_EQ(in->Eof(), false);
    while (in->GetLine(&line)) {
      count++;
    };
    EXPECT_EQ(in->GetLength(), input.size());
    EXPECT_EQ(count, param.while_count);
    EXPECT_EQ(line, param.last_line);
    EXPECT_EQ(in->Tellg(), input.size());
    EXPECT_EQ(in->operator bool(), false);
    EXPECT_EQ(in->operator!(), true);
    EXPECT_EQ(in->Eof(), true);

    in->Seekg(1);  // <<<<
    count = 0;
    EXPECT_EQ(in->Eof(), false);
    while (in->GetLine(&line)) {
      count++;
    };
    EXPECT_EQ(count, param.while_count);
    EXPECT_EQ(line, param.last_line);
    EXPECT_EQ(in->Tellg(), input.size());
    EXPECT_EQ(in->Eof(), true);
  }

  {
    std::string buf;
    std::unique_ptr<OutputStream> out(new MemOutputStream(&buf));
    out->Write(param.data, strlen(param.data));
    out->Flush();
    EXPECT_EQ(buf.size(), strlen(param.data));
    out->Write(std::string(param.last_line));
    EXPECT_EQ(strlen(param.data) + strlen(param.last_line), out->Tellp());
    out->Close();
    EXPECT_EQ(buf.substr(0, strlen(param.data)), param.data);
    EXPECT_EQ(buf.substr(strlen(param.data), strlen(param.last_line)),
              param.last_line);
  }
}

TEST_P(IOTest, FileIO) {
  auto param = GetParam();
  std::filesystem::current_path(std::filesystem::temp_directory_path());
  std::string file_name(fmt::format("{}.test", std::time(nullptr)));
  {
    std::unique_ptr<OutputStream> out(new FileOutputStream(file_name));
    out->Write(std::string(param.data, strlen(param.data) - 2));
    out->Flush();
    EXPECT_EQ(std::filesystem::file_size(file_name), strlen(param.data) - 2);
    out->Write(param.data + strlen(param.data) - 2, 2);
    EXPECT_EQ(strlen(param.data), out->Tellp());
    out.reset();
    EXPECT_EQ(std::filesystem::file_size(file_name), strlen(param.data));
  }
  {
    std::unique_ptr<InputStream> in(new FileInputStream(file_name));
    EXPECT_EQ(strlen(param.data), in->GetLength());
    int count = 0;
    std::string line;
    EXPECT_EQ(in->Eof(), false);
    while (in->GetLine(&line)) {
      count++;
    };
    EXPECT_EQ(in->GetLength(), strlen(param.data));
    EXPECT_EQ(count, param.while_count);
    EXPECT_EQ(line, param.last_line);
    EXPECT_EQ(in->Tellg(), strlen(param.data));
    EXPECT_EQ(in->operator bool(), false);
    EXPECT_EQ(in->operator!(), true);
    EXPECT_EQ(in->Eof(), true);

    in->Seekg(1);  // <<<<
    count = 0;
    EXPECT_EQ(in->Eof(), false);
    while (in->GetLine(&line)) {
      count++;
    };
    EXPECT_EQ(count, param.while_count);
    EXPECT_EQ(line, param.last_line);
    EXPECT_EQ(in->Tellg(), strlen(param.data));
    EXPECT_EQ(in->Eof(), true);
  }
}

}  // namespace yacl::io