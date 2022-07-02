#include "yasl/utils/hamming.h"

#include "gtest/gtest.h"

namespace yasl {

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

}  // namespace yasl