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

#include "yacl/crypto/primitives/tpre/hash.h"

#include "gtest/gtest.h"

#include "yacl/base/exception.h"
#include "yacl/crypto/base/mpint/mp_int.h"

namespace yacl::crypto::test {
class HashTest : public testing::Test {};

TEST(HashTest, Test1) {
  MPInt zero(0);
  auto hash_value = CipherHash("tpre", "sm2");

  std::cout << "hash_value = " << hash_value.ToHexString() << std::endl;
  EXPECT_TRUE(hash_value > zero);
  EXPECT_EQ(hash_value.ToHexString(),
            "B465B279C1693E0C34810B93F8A5095B93F912E3B4DD13265E5157F5B2A25895");
}

}  // namespace yacl::crypto::test
