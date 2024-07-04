// Copyright 2024 Ant Group Co., Ltd.
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

#include "yacl/io/circuit/bristol_fashion.h"

#include <cstdint>
#include <ctime>
#include <filesystem>

#include "fmt/format.h"
#include "gtest/gtest.h"
#include "spdlog/spdlog.h"

#include "yacl/base/exception.h"
#include "yacl/io/stream/file_io.h"

namespace yacl::io {

namespace {

std::string GetAesBfPath() {
  return fmt::format("{}/yacl/io/circuit/data/aes_128.txt",
                     std::filesystem::current_path().string());
}

}  // namespace

TEST(BasicTest, SimpleTest) {
  CircuitReader reader(GetAesBfPath());
  reader.ReadMeta();
  reader.ReadAllGates();
}

TEST(BasicTest, SimpleTest1) {
  CircuitReader reader(GetAesBfPath());
  reader.ReadAll();
}

TEST(BasicTest, SimpleTest2) {
  CircuitReader reader(GetAesBfPath());
  reader.ReadAllGates();
}

TEST(BasicTest, SimpleTest3) {
  CircuitReader reader(GetAesBfPath());
  reader.ReadAll();

  reader.StealCirc();
  EXPECT_THROW(reader.StealCirc(),
               yacl::Exception);  // you should not steal twice
}

TEST(BasicTest, SimpleTest4) {
  CircuitReader reader(GetAesBfPath());
  reader.ReadAll();

  reader.Reset();
  EXPECT_THROW(reader.StealCirc(),
               yacl::Exception);  // you should not steal
}

}  // namespace yacl::io
