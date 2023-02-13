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

#include "yacl/utils/hamming.h"

#include "gtest/gtest.h"

namespace yacl {

TEST(Hamming, Weight) {
  uint64_t x = 0xA0A0A0;
  uint64_t y = 0x0A0A0A;

  EXPECT_EQ(HammingWeight(x), 6);
  EXPECT_EQ(HammingWeight(x), HammingWeight(y));

  uint128_t a = std::numeric_limits<uint128_t>::max();
  int128_t b = MakeInt128(uint64_t(1) << 63, 0);
  EXPECT_EQ(HammingWeight(a), 128);
  EXPECT_EQ(HammingWeight(b), 1);
}

TEST(Hamming, Distance) {
  uint64_t x = 0xA0A0A0;
  uint64_t y = 0x0A0A0A;

  EXPECT_EQ(HammingDistance(x, y), 12);
}

}  // namespace yacl