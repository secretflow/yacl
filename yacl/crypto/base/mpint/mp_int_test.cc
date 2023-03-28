// Copyright 2022 Ant Group Co., Ltd.
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

#include "yacl/crypto/base/mpint/mp_int.h"

#include "gtest/gtest.h"

namespace yacl::crypto::test {

class MPIntTest : public testing::Test {};

TEST_F(MPIntTest, CompareWorks) {
  MPInt x1(256);
  MPInt x2(257);

  EXPECT_TRUE(x1.Compare(x2) < 0);
  EXPECT_TRUE(x1 < x2);
  EXPECT_TRUE(x1 <= x2);
  EXPECT_TRUE(x2 > x1);
  EXPECT_TRUE(x2 >= x1);
}

TEST_F(MPIntTest, ArithmeticWorks) {
  MPInt x1(23);
  MPInt x2(37);

  EXPECT_TRUE(x1 + x2 == MPInt(23 + 37));
  EXPECT_TRUE(x2 + x1 == MPInt(37 + 23));
  EXPECT_TRUE(x1 - x2 == MPInt(23 - 37));
  EXPECT_TRUE(x2 - x1 == MPInt(37 - 23));
  EXPECT_TRUE(x1 * x2 == MPInt(23 * 37));
  EXPECT_TRUE(x2 * x1 == MPInt(37 * 23));
  EXPECT_TRUE(x1 / x2 == MPInt(23 / 37));
  EXPECT_TRUE(x2 / x1 == MPInt(37 / 23));

  EXPECT_EQ(x1.AddMod(x2, MPInt(5)), MPInt((23 + 37) % 5));
  EXPECT_EQ(x2.SubMod(x1, MPInt(5)), MPInt((37 - 23) % 5));
  EXPECT_EQ(x1.MulMod(x2, MPInt(5)), MPInt((23 * 37) % 5));

  MPInt c;
  MPInt::Add(x1, x2, &c);
  EXPECT_TRUE(c == MPInt(23 + 37));
  MPInt::Sub(x1, x2, &c);
  EXPECT_TRUE(c == MPInt(23 - 37));
  MPInt::Mul(x1, x2, &c);
  EXPECT_TRUE(c == MPInt(23 * 37));

  EXPECT_TRUE(x1.Mul(3) == MPInt(23 * 3));
  x1.MulInplace(3);
  EXPECT_TRUE(x1 == MPInt(23 * 3));
}

TEST_F(MPIntTest, PowWorks) {
  EXPECT_EQ(MPInt::_2_.Pow(0), MPInt::_1_);
  EXPECT_EQ(MPInt::_2_.Pow(1), MPInt::_2_);
  EXPECT_EQ(MPInt::_2_.Pow(2), 4_mp);
  EXPECT_EQ(MPInt::_2_.Pow(3), 8_mp);

  EXPECT_EQ(MPInt::_2_.Pow(255), 1_mp << 255);
  EXPECT_EQ(
      MPInt::_2_.Pow(255) - 19_mp,
      "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"_mp);

  // PowMod
  EXPECT_EQ(MPInt::_2_.PowMod(0_mp, 5_mp), MPInt::_1_);
  EXPECT_EQ(MPInt::_2_.PowMod(1_mp, 5_mp), MPInt::_2_);
  EXPECT_EQ(MPInt::_2_.PowMod(2_mp, 5_mp), 4_mp);
  EXPECT_EQ(MPInt::_2_.PowMod(3_mp, 5_mp), 3_mp);
}

TEST_F(MPIntTest, CtorZeroWorks) {
  MPInt x;
  EXPECT_TRUE(x.IsZero());

  MPInt x2(0);
  EXPECT_TRUE(x2.IsZero());

  MPInt x3(0, 2048);
  EXPECT_TRUE(x3.IsZero());
}

TEST_F(MPIntTest, CtorWorks) {
  MPInt x1(-123456);
  MPInt x2(2345, 512);

  EXPECT_TRUE(x1.IsNegative());
  EXPECT_FALSE(x2.IsNegative());
  EXPECT_TRUE(x1.Compare(x2) < 0);

  EXPECT_EQ(MPInt("0").Get<int64_t>(), 0);
  EXPECT_EQ(MPInt("0777").Get<int64_t>(), 511);
  EXPECT_EQ(MPInt("520").Get<int64_t>(), 520);
  EXPECT_EQ(MPInt("0xabc").Get<int64_t>(), 2748);
  EXPECT_EQ(MPInt("0xABC").Get<int64_t>(), 2748);
  EXPECT_EQ(MPInt("0Xabc").Get<int64_t>(), 2748);
  EXPECT_EQ(MPInt("-0").Get<int64_t>(), 0);
  EXPECT_EQ(MPInt("-0777").Get<int64_t>(), -511);
  EXPECT_EQ(MPInt("-520").Get<int64_t>(), -520);
  EXPECT_EQ(MPInt("-0xabc").Get<int64_t>(), -2748);
  EXPECT_EQ(MPInt("-0xABC").Get<int64_t>(), -2748);
  EXPECT_EQ(MPInt("-0Xabc").Get<int64_t>(), -2748);
  EXPECT_EQ(MPInt("+0").Get<int64_t>(), 0);
  EXPECT_EQ(MPInt("+0777").Get<int64_t>(), 511);
  EXPECT_EQ(MPInt("+520").Get<int64_t>(), 520);
  EXPECT_EQ(MPInt("+0xabc").Get<int64_t>(), 2748);
  EXPECT_EQ(MPInt("+0xABC").Get<int64_t>(), 2748);
  EXPECT_EQ(MPInt("+0Xabc").Get<int64_t>(), 2748);
}

TEST_F(MPIntTest, InvertModWorks) {
  MPInt a(667);
  MPInt::InvertMod(a, MPInt(561613), &a);
  EXPECT_EQ(842, a.Get<double>());
}

TEST_F(MPIntTest, ToStringWorks) {
  MPInt x1;
  MPInt x2(static_cast<int64_t>(0x12345abcdef));

  EXPECT_EQ(x1.ToHexString(), "0");
  EXPECT_EQ(x2.ToHexString(), "12345ABCDEF");
}

TEST_F(MPIntTest, NegativeMPIntToStringWorks) {
  MPInt x1(-12345678);
  ASSERT_TRUE(x1.IsNegative());
  EXPECT_EQ(x1.ToString(), "-12345678");
  EXPECT_EQ(x1.ToHexString(), "-BC614E");
}

TEST_F(MPIntTest, SerializeWorks) {
  MPInt x1(1234567890);
  MPInt x2(-1234567890);

  yacl::Buffer x1_repr = x1.Serialize();
  yacl::Buffer x2_repr = x2.Serialize();

  ASSERT_TRUE(x1_repr.size() > 0);
  ASSERT_TRUE(x2_repr.size() > 0);

  MPInt x1_value, x2_value;
  x1_value.Deserialize(x1_repr);
  x2_value.Deserialize(x2_repr);

  EXPECT_TRUE(x1.Compare(x1_value) == 0);
  EXPECT_TRUE(x2.Compare(x2_value) == 0);
}

TEST_F(MPIntTest, MsgpackWorks) {
  MPInt x1(-1234567890);

  msgpack::sbuffer buf;
  msgpack::pack(buf, x1);
  ASSERT_GT(buf.size(), x1.Serialize().size());

  MPInt x2;
  msgpack::object_handle oh = msgpack::unpack(buf.data(), buf.size());
  const msgpack::object& obj = oh.get();
  obj.convert(x2);
  ASSERT_EQ(x1, x2);
}

TEST_F(MPIntTest, RandPrimeOverWorks) {
  // basic test
  int bit_size = 256;
  MPInt x;
  MPInt::RandPrimeOver(bit_size, &x, PrimeType::Normal);
  EXPECT_GE(x.BitCount(), bit_size);
  EXPECT_TRUE(x.IsPrime());

  MPInt::RandPrimeOver(bit_size, &x, PrimeType::BBS);
  EXPECT_GE(x.BitCount(), bit_size);
  EXPECT_TRUE(x.IsPrime());
  EXPECT_EQ(x % MPInt(4), MPInt(3));

  MPInt::RandPrimeOver(bit_size, &x, PrimeType::FastSafe);
  EXPECT_GE(x.BitCount(), bit_size);
  EXPECT_TRUE(x.IsPrime());
  EXPECT_TRUE((x / MPInt::_2_).IsPrime());

  // test different bit size
  MPInt::RandPrimeOver(128, &x, PrimeType::FastSafe);
  EXPECT_TRUE(x.IsPrime());
  EXPECT_TRUE((x / MPInt::_2_).IsPrime());

  MPInt::RandPrimeOver(512, &x, PrimeType::FastSafe);
  EXPECT_TRUE(x.IsPrime());
  EXPECT_TRUE((x / MPInt::_2_).IsPrime());

  MPInt::RandPrimeOver(1024, &x, PrimeType::FastSafe);
  EXPECT_TRUE(x.IsPrime());
  EXPECT_TRUE((x / MPInt::_2_).IsPrime());
}

TEST_F(MPIntTest, RandomWorks) {
  for (int i = 0; i < 10; ++i) {
    int bit_size = 240;
    MPInt r;
    MPInt::RandomRoundDown(bit_size, &r);  // 240 bits

    EXPECT_LE(r.BitCount(), bit_size);
    // The probability that the first 20 digits are all 0 is less than 2^20
    EXPECT_GE(r.BitCount(), bit_size - 20);

    MPInt::RandomRoundUp(bit_size, &r);  // 240 bits
    EXPECT_LE(r.BitCount(), bit_size);
    EXPECT_GE(r.BitCount(), bit_size - 20);

    bit_size = 105;
    MPInt::RandomRoundDown(bit_size, &r);  // 60 bits
    EXPECT_LE(r.BitCount(), 60);
    EXPECT_GE(r.BitCount(), 60 - 20);

    MPInt::RandomRoundUp(bit_size, &r);  // 120 bits
    EXPECT_LE(r.BitCount(), 120);
    EXPECT_GE(r.BitCount(), 120 - 20);

    MPInt::RandomMonicExactBits(1, &r);
    EXPECT_EQ(r, MPInt::_1_);

    MPInt::RandomMonicExactBits(2, &r);
    EXPECT_TRUE(r == MPInt(2) || r == MPInt(3));

    // test RandomExactBits
    MPInt::RandomExactBits(0, &r);
    EXPECT_EQ(r.BitCount(), 0);

    std::vector<size_t> cases = {59,  60,  61,   119,  120,
                                 121, 461, 2048, 3072, 10000};
    for (const auto& c : cases) {
      int count = 0;
      do {
        MPInt::RandomExactBits(c, &r);
        ASSERT_LE(r.BitCount(), c);
        ASSERT_LT(count++, 100)
            << "RandomExactBits fail after 100 loop, case=" << c;
      } while (r.BitCount() == c);

      MPInt::RandomMonicExactBits(c, &r);
      EXPECT_EQ(r.BitCount(), c);
    }
  }
}

TEST_F(MPIntTest, ToBytesWorks) {
  MPInt a(0x1234);
  auto buf = a.ToBytes(2, Endian::little);
  EXPECT_EQ(buf.data<char>()[0], 0x34);
  EXPECT_EQ(buf.data<char>()[1], 0x12);

  buf = a.ToBytes(2, Endian::big);
  EXPECT_EQ(buf.data<char>()[0], 0x12);
  EXPECT_EQ(buf.data<char>()[1], 0x34);

  a = MPInt(0x123456);
  buf = a.ToBytes(2, Endian::native);
  EXPECT_EQ(buf.data<uint16_t>()[0], 0x3456);

  a = MPInt(-1);
  EXPECT_EQ(a.ToBytes(10, Endian::little), a.ToBytes(10, Endian::big));
}

TEST_F(MPIntTest, CustomPowWorks) {
  // 3^1234
  MPInt res = MPInt::SlowCustomPow<MPInt>(
      1_mp, 3_mp, 1234_mp, [](MPInt* a, const MPInt& b) -> void { *a *= b; });
  EXPECT_EQ(res, (3_mp).Pow(1234));

  // 23 * 90
  res = MPInt::SlowCustomPow<MPInt>(
      0_mp, 23_mp, 90_mp, [](MPInt* a, const MPInt& b) -> void { *a += b; });
  EXPECT_EQ(res.Get<int64_t>(), 23 * 90);
}

class MPIntToBytesTest : public ::testing::TestWithParam<int128_t> {};

INSTANTIATE_TEST_SUITE_P(
    SmallNumbers, MPIntToBytesTest,
    ::testing::Values(0, 1, -1, 2, -2, 4, -4, 1024, -1024, 100000, -100000,
                      std::numeric_limits<int32_t>::max() / 2,
                      -(std::numeric_limits<int32_t>::max() / 2),
                      std::numeric_limits<int32_t>::max(),
                      std::numeric_limits<int32_t>::min(),
                      std::numeric_limits<int64_t>::max() / 2,
                      -(std::numeric_limits<int64_t>::max() / 2),
                      std::numeric_limits<int64_t>::max(),
                      std::numeric_limits<int64_t>::min()));

// There is more tests in python end
TEST_P(MPIntToBytesTest, NativeWorks) {
  MPInt num(GetParam());
  auto buf = num.ToBytes(sizeof(int32_t));
  EXPECT_EQ(static_cast<int32_t>(GetParam()), buf.data<int32_t>()[0]);

  buf = num.ToBytes(sizeof(int64_t));
  EXPECT_EQ(static_cast<int64_t>(GetParam()), buf.data<int64_t>()[0]);
}

}  // namespace yacl::crypto::test
