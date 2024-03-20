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

#include "yacl/crypto/rand/rand.h"

#include "gtest/gtest.h"

namespace yacl::crypto {

#define TEST_GENERIC_TYPE_RAND_FUNC(FUNC, ...) \
  TEST(GenericRandTest, Fast##FUNC##Test) {    \
    auto tmp1 = Fast##FUNC(__VA_ARGS__);       \
    auto tmp2 = Fast##FUNC(__VA_ARGS__);       \
                                               \
    /* should be different*/                   \
    EXPECT_TRUE(tmp1 != tmp2);                 \
  }                                            \
                                               \
  TEST(GenericRandTest, Secure##FUNC##Test) {  \
    auto tmp1 = Secure##FUNC(__VA_ARGS__);     \
    auto tmp2 = Secure##FUNC(__VA_ARGS__);     \
                                               \
    /* should be different*/                   \
    EXPECT_TRUE(tmp1 != tmp2);                 \
  }

TEST_GENERIC_TYPE_RAND_FUNC(RandU64);
TEST_GENERIC_TYPE_RAND_FUNC(RandU128);
TEST_GENERIC_TYPE_RAND_FUNC(RandSeed);
TEST_GENERIC_TYPE_RAND_FUNC(RandBytes, 10);
TEST_GENERIC_TYPE_RAND_FUNC(RandBits, 10);

}  // namespace yacl::crypto
