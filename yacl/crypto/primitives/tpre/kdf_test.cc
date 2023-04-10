// Copyright 2023 Chengfang Financial Technology Co., Ltd.
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

#include "yacl/crypto/primitives/tpre/kdf.h"

#include <iostream>
#include <string>

#include "absl/strings/escaping.h"
#include "gtest/gtest.h"

namespace yacl::crypto::test {

TEST(KDFTest, Test1) {
  std::vector<uint8_t> key = KDF("key_str", 16);
  std::string key_str = absl::BytesToHexString(
      absl::string_view((const char*)key.data(), key.size()));

  EXPECT_EQ(key_str, "93a42c6b4c02ab6956f0095787c67e5e");
}
}  // namespace yacl::crypto::test
