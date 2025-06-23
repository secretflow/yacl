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

#include "yacl/math/bigint/bigint.h"

#include "gmock/gmock-matchers.h"
#include "gtest/gtest.h"

namespace yacl::math::test {

class BigIntArithTest
    : public ::testing::TestWithParam<std::shared_ptr<IBigIntLib>> {
 protected:
  std::shared_ptr<IBigIntLib> lib_ = GetParam();
};

TEST_P(BigIntArithTest, Construct) {
  BigInt zero;
  EXPECT_TRUE(zero.IsZero());

  BigInt a("123456789012345678901234567890", 10, lib_);
  EXPECT_EQ(a.ToString(), "123456789012345678901234567890");

  BigInt b("1234567890abcdef1234567890abcdef", 16, lib_);
  EXPECT_EQ(b.ToString(), "24197857200151252728969465429440056815");

  if (lib_->GetLibraryName() != "openssl") {
    BigInt c("1010101010101010101010101010101010101010", 2, lib_);
    EXPECT_EQ(c.ToString(), "733007751850");
  }

  BigInt d(1234567890, lib_);
  EXPECT_EQ(d.ToString(), "1234567890");

  BigInt e(-1234567890, lib_);
  EXPECT_EQ(e.ToString(), "-1234567890");

  BigInt f(std::numeric_limits<int64_t>::max(), lib_);
  EXPECT_EQ(f.ToString(), "9223372036854775807");

  BigInt g(std::numeric_limits<int64_t>::min(), lib_);
  EXPECT_EQ(g.ToString(), "-9223372036854775808");

  BigInt h(0, lib_);
  EXPECT_EQ(h.ToString(), "0");

  BigInt i(lib_);
  EXPECT_EQ(i.ToString(), "0");

  BigInt j(100, 128, lib_);
  EXPECT_EQ(j.ToString(), "100");

  BigInt k(Int128Min(), lib_);
  EXPECT_EQ(k.ToString(), "-170141183460469231731687303715884105728");

  BigInt l(Int128Min(), 256, lib_);
  EXPECT_EQ(l.ToString(), "-170141183460469231731687303715884105728");

  BigInt m(Int128Max(), lib_);
  EXPECT_EQ(m.ToString(), "170141183460469231731687303715884105727");

  BigInt n(Int128Max(), 256, lib_);
  EXPECT_EQ(n.ToString(), "170141183460469231731687303715884105727");

  BigInt o(Uint128Max(), lib_);
  EXPECT_EQ(o.ToString(), "340282366920938463463374607431768211455");

  BigInt p(Uint128Max(), 128, lib_);
  EXPECT_EQ(p.ToString(), "340282366920938463463374607431768211455");
}

TEST_P(BigIntArithTest, Set) {
  BigInt a(lib_);

  a.Set("123456789012345", 10);
  EXPECT_EQ(a.ToString(), "123456789012345");

  a.Set("-7048860ddf79", 16);
  EXPECT_EQ(a.ToString(), "-123456789012345");

  a.Set(123456789000.345);
  EXPECT_EQ(a.Get<int64_t>(), 123456789000L);

  a.Set(123456789000.567);
  EXPECT_EQ(a.Get<int64_t>(), 123456789000L);

  a.Set(123456789000.999);
  EXPECT_EQ(a.Get<int64_t>(), 123456789000L);

  a.Set(-123456789000.999);
  EXPECT_EQ(a.Get<int64_t>(), -123456789000L);

  a.Set(123456.7F);
  EXPECT_EQ(a.Get<int32_t>(), 123456);

  a.Set(12345678901234567890.0);
  EXPECT_DOUBLE_EQ(a.Get<double>(), 12345678901234567890.0);

  a.Set(12345678901234567890.0F);
  EXPECT_FLOAT_EQ(a.Get<float>(), 12345678901234567890.0F);

  a.Set(123456.789e+100);
  EXPECT_DOUBLE_EQ(a.Get<double>(), 123456.789e+100);
}

TEST_P(BigIntArithTest, Get) {
  BigInt a(lib_);
  EXPECT_EQ(a.Get<int8_t>(), 0);

  a.Set(-100);
  EXPECT_EQ(a.Get<int8_t>(), -100);
  EXPECT_EQ(a.Get<uint8_t>(), 100);
  EXPECT_EQ(a.Get<int64_t>(), -100);
  EXPECT_EQ(a.Get<uint64_t>(), 100);
  EXPECT_EQ(a.Get<int128_t>(), -100);
  EXPECT_EQ(a.Get<uint128_t>(), 100);
  EXPECT_DOUBLE_EQ(a.Get<double>(), -100.0);
  EXPECT_FLOAT_EQ(a.Get<float>(), -100.0F);

  a.Set(-1000000);
  EXPECT_EQ(a.Get<int8_t>(), -64);
  EXPECT_EQ(a.Get<uint8_t>(), 64);
  EXPECT_EQ(a.Get<int64_t>(), -1000000);
  EXPECT_EQ(a.Get<uint64_t>(), 1000000);
  EXPECT_EQ(a.Get<int128_t>(), -1000000);
  EXPECT_EQ(a.Get<uint128_t>(), 1000000);
  EXPECT_DOUBLE_EQ(a.Get<double>(), -1000000.0);
  EXPECT_FLOAT_EQ(a.Get<float>(), -1000000.0F);

  a.Set(std::numeric_limits<int64_t>::min());
  EXPECT_EQ(a.Get<int16_t>(), 0);
  EXPECT_EQ(a.Get<uint16_t>(), 0);
  EXPECT_EQ(a.Get<int64_t>(), std::numeric_limits<int64_t>::min());
  EXPECT_EQ(a.Get<uint64_t>(), std::numeric_limits<uint64_t>::max() / 2 + 1);
  EXPECT_DOUBLE_EQ(a.Get<double>(), -9223372036854775808.0);
  EXPECT_FLOAT_EQ(a.Get<float>(), -9223372036854775808.0F);

  a.Set(std::numeric_limits<int64_t>::max());
  EXPECT_EQ(a.Get<int16_t>(), -1);
  EXPECT_EQ(a.Get<uint16_t>(), std::numeric_limits<uint16_t>::max());
  EXPECT_EQ(a.Get<int64_t>(), std::numeric_limits<int64_t>::max());
  EXPECT_EQ(a.Get<uint64_t>(), std::numeric_limits<int64_t>::max());
  EXPECT_DOUBLE_EQ(a.Get<double>(), 9223372036854775807.0);
  EXPECT_FLOAT_EQ(a.Get<float>(), 9223372036854775807.0F);

  a.Set(std::numeric_limits<uint64_t>::max());
  EXPECT_EQ(a.Get<int64_t>(), -1);
  EXPECT_EQ(a.Get<uint64_t>(), std::numeric_limits<uint64_t>::max());
  EXPECT_DOUBLE_EQ(a.Get<double>(), 18446744073709551615.0);
  EXPECT_FLOAT_EQ(a.Get<float>(), 18446744073709551615.0F);

  a.Set(Int128Min());
  EXPECT_EQ(a.Get<int64_t>(), 0);
  EXPECT_EQ(a.Get<uint64_t>(), 0);
  EXPECT_EQ(a.Get<int128_t>(), Int128Min());
  EXPECT_EQ(a.Get<uint128_t>(), Uint128Max() / 2 + 1);
  EXPECT_DOUBLE_EQ(a.Get<double>(), -170141183460469231731687303715884105728.0);
  EXPECT_FLOAT_EQ(a.Get<float>(), -170141183460469231731687303715884105728.0F);

  a.Set(Int128Max());
  EXPECT_EQ(a.Get<int64_t>(), -1);
  EXPECT_EQ(a.Get<uint64_t>(), std::numeric_limits<uint64_t>::max());
  EXPECT_EQ(a.Get<int128_t>(), Int128Max());
  EXPECT_EQ(a.Get<uint128_t>(), Int128Max());
  EXPECT_DOUBLE_EQ(a.Get<double>(), 170141183460469231731687303715884105727.0);
  EXPECT_FLOAT_EQ(a.Get<float>(), 170141183460469231731687303715884105727.0F);

  a.Set(Uint128Max());
  EXPECT_EQ(a.Get<int64_t>(), -1);
  EXPECT_EQ(a.Get<uint64_t>(), std::numeric_limits<uint64_t>::max());
  EXPECT_EQ(a.Get<int128_t>(), -1);
  EXPECT_EQ(a.Get<uint128_t>(), Uint128Max());
  EXPECT_DOUBLE_EQ(a.Get<double>(), 340282366920938463463374607431768211455.0);
  EXPECT_FLOAT_EQ(a.Get<float>(), std::numeric_limits<float>::infinity());

  a.Set("-123456789012345678901234567890123456789012345678901234567890", 10);
  EXPECT_DOUBLE_EQ(a.Get<double>(), -1.2345678901234566e+59);
  EXPECT_FLOAT_EQ(a.Get<float>(), -std::numeric_limits<float>::infinity());

  a.Set("123456789012345678901234567890123456789012345678901234567890", 10);
  EXPECT_DOUBLE_EQ(a.Get<double>(), 1.2345678901234566e+59);
  EXPECT_FLOAT_EQ(a.Get<float>(), std::numeric_limits<float>::infinity());
}

TEST_P(BigIntArithTest, Add) {
  BigInt a("123456789012345678901234567890", 10, lib_);
  BigInt b("987654321098765432109876543210", 10, lib_);

  auto c = a + b;
  EXPECT_EQ(c.ToString(), "1111111110111111111011111111100");
}

TEST_P(BigIntArithTest, AddAssign) {
  BigInt a("123456789012345678901234567890", 10, lib_);
  BigInt b("987654321098765432109876543210", 10, lib_);

  a += b;
  EXPECT_EQ(a.ToString(), "1111111110111111111011111111100");

  a += BigInt("112233445566778899009988776655", 10, lib_);
  EXPECT_EQ(a.ToString(), "1223344555677890010021099887755");
}

TEST_P(BigIntArithTest, AddUint64) {
  BigInt a("123456789012345678901234567890", 10, lib_);

  auto c = a + 123456789098765UL;
  EXPECT_EQ(c.ToString(), "123456789012345802358023666655");

  c = a + 18446744073709551612UL;
  EXPECT_EQ(c.ToString(), "123456789030792422974944119502");
}

TEST_P(BigIntArithTest, AddAssignUint64) {
  BigInt a("123456789012345678901234567890", 10, lib_);
  a += 123456789098765UL;
  EXPECT_EQ(a.ToString(), "123456789012345802358023666655");
}

TEST_P(BigIntArithTest, Sub) {
  BigInt a("123456789012345678901234567890", 10, lib_);
  BigInt b("987654321098765432109876543210", 10, lib_);

  auto c = a - b;
  EXPECT_EQ(c.ToString(), "-864197532086419753208641975320");
}

TEST_P(BigIntArithTest, SubAssign) {
  BigInt a("123456789012345678901234567890", 10, lib_);
  BigInt b("987654321098765432109876543210", 10, lib_);

  a -= b;
  EXPECT_EQ(a.ToString(), "-864197532086419753208641975320");

  a -= BigInt("112233445566778899009988776655", 10, lib_);
  EXPECT_EQ(a.ToString(), "-976430977653198652218630751975");
}

TEST_P(BigIntArithTest, SubUint64) {
  BigInt a("123456789012345678901234567890", 10, lib_);

  auto c = a - 123456789098765UL;
  EXPECT_EQ(c.ToString(), "123456789012345555444445469125");

  c = a - 1152921504606846975UL;
  EXPECT_EQ(c.ToString(), "123456789011192757396627720915");
}

TEST_P(BigIntArithTest, SubAssignUint64) {
  BigInt a("123456789012345678901234567890", 10, lib_);
  a -= 123456789098765UL;
  EXPECT_EQ(a.ToString(), "123456789012345555444445469125");
}

TEST_P(BigIntArithTest, Mul) {
  BigInt a("123456789", 10, lib_);
  BigInt b("987654321", 10, lib_);

  auto c = a * b;
  EXPECT_EQ(c.ToString(), "121932631112635269");
}

TEST_P(BigIntArithTest, MulAssign) {
  BigInt a("123456789", 10, lib_);
  BigInt b("987654321", 10, lib_);

  a *= b;
  EXPECT_EQ(a.ToString(), "121932631112635269");
}

TEST_P(BigIntArithTest, MulUint64) {
  BigInt a("123456789", 10, lib_);

  auto c = a * 123456789UL;
  EXPECT_EQ(c.ToString(), "15241578750190521");
}

TEST_P(BigIntArithTest, MulAssignUint64) {
  BigInt a("123456789", 10, lib_);
  a *= 123456789UL;
  EXPECT_EQ(a.ToString(), "15241578750190521");
}

TEST_P(BigIntArithTest, Div) {
  BigInt a("123456789012345678901234567890", 10, lib_);
  BigInt b("9876543210987654321", 10, lib_);
  BigInt zero(0, lib_);

  auto c = a / b;
  EXPECT_EQ(c.ToString(), "12499999886");

  c = a / (-b);
  EXPECT_EQ(c.ToString(), "-12499999887");

  c = (-a) / b;
  EXPECT_EQ(c.ToString(), "-12499999887");

  c = (-a) / (-b);
  EXPECT_EQ(c.ToString(), "12499999886");

  c = zero / b;
  EXPECT_EQ(c.ToString(), "0");
  c = zero / (-b);
  EXPECT_EQ(c.ToString(), "0");
}

TEST_P(BigIntArithTest, DivExact) {
  BigInt a("100000000000", 10, lib_);
  BigInt b("1000000", 10, lib_);

  auto c = a / b;
  EXPECT_EQ(c.ToString(), "100000");

  c = a / (-b);
  EXPECT_EQ(c.ToString(), "-100000");

  c = (-a) / b;
  EXPECT_EQ(c.ToString(), "-100000");

  c = (-a) / (-b);
  EXPECT_EQ(c.ToString(), "100000");
}

TEST_P(BigIntArithTest, DivAssign) {
  BigInt a("123456789012345678901234567890", 10, lib_);
  BigInt b("9876543210987654321", 10, lib_);
  BigInt zero(0, lib_);

  auto c = a;
  c /= b;
  EXPECT_EQ(c.ToString(), "12499999886");

  c = a;
  c /= (-b);
  EXPECT_EQ(c.ToString(), "-12499999887");

  c = -a;
  c /= b;
  EXPECT_EQ(c.ToString(), "-12499999887");

  c = -a;
  c /= (-b);
  EXPECT_EQ(c.ToString(), "12499999886");

  zero /= b;
  EXPECT_EQ(zero.ToString(), "0");
  zero /= (-b);
  EXPECT_EQ(zero.ToString(), "0");
}

TEST_P(BigIntArithTest, DivAssignExact) {
  BigInt a("100000000000", 10, lib_);
  BigInt b("1000000", 10, lib_);

  auto c = a;
  c /= b;
  EXPECT_EQ(c.ToString(), "100000");

  c = a;
  c /= (-b);
  EXPECT_EQ(c.ToString(), "-100000");

  c = -a;
  c /= b;
  EXPECT_EQ(c.ToString(), "-100000");

  c = -a;
  c /= (-b);
  EXPECT_EQ(c.ToString(), "100000");
}

TEST_P(BigIntArithTest, DivUint64) {
  BigInt a("123456789012345678901234567890", 10, lib_);
  BigInt zero(0, lib_);

  auto c = a / 987654321UL;
  EXPECT_EQ(c.ToString(), "124999998873437499901");

  c = (-a) / 987654321UL;
  EXPECT_EQ(c.ToString(), "-124999998873437499902");

  c = a / 1152921504606846999UL;
  EXPECT_EQ(c.ToString(), "107081695084");

  c = (-a) / 1152921504606846999UL;
  EXPECT_EQ(c.ToString(), "-107081695085");

  c = zero / 987654321UL;
  EXPECT_EQ(c.ToString(), "0");
  c = zero / 1152921504606846999UL;
  EXPECT_EQ(c.ToString(), "0");
}

TEST_P(BigIntArithTest, DivUint64Exact) {
  BigInt a("100000000000", 10, lib_);
  auto c = a / 1000000UL;
  EXPECT_EQ(c.ToString(), "100000");

  c = (-a) / 1000000UL;
  EXPECT_EQ(c.ToString(), "-100000");
}

TEST_P(BigIntArithTest, DivAssignUint64) {
  BigInt a("123456789012345678901234567890", 10, lib_);
  BigInt zero(0, lib_);

  auto c = a;
  c /= 987654321UL;
  EXPECT_EQ(c.ToString(), "124999998873437499901");

  c = -a;
  c /= 987654321UL;
  EXPECT_EQ(c.ToString(), "-124999998873437499902");

  c = a;
  c /= 1152921504606846999UL;
  EXPECT_EQ(c.ToString(), "107081695084");

  c = -a;
  c /= 1152921504606846999UL;
  EXPECT_EQ(c.ToString(), "-107081695085");

  zero /= 987654321UL;
  EXPECT_EQ(zero.ToString(), "0");
  zero /= 1152921504606846999UL;
  EXPECT_EQ(zero.ToString(), "0");
}

TEST_P(BigIntArithTest, DivAssignUint64Exact) {
  BigInt a("100000000000", 10, lib_);
  auto c = a;
  c /= 1000000UL;
  EXPECT_EQ(c.ToString(), "100000");

  c = -a;
  c /= 1000000UL;
  EXPECT_EQ(c.ToString(), "-100000");
}

TEST_P(BigIntArithTest, Mod) {
  BigInt a("123456789012345678901234567890", 10, lib_);
  BigInt b("9876543210987654321", 10, lib_);
  BigInt zero(0, lib_);

  auto c = a % b;
  EXPECT_EQ(c.ToString(), "925925941327160484");

  c = a % (-b);
  EXPECT_EQ(c.ToString(), "-8950617269660493837");

  c = (-a) % b;
  EXPECT_EQ(c.ToString(), "8950617269660493837");

  c = (-a) % (-b);
  EXPECT_EQ(c.ToString(), "-925925941327160484");

  c = zero % b;
  EXPECT_EQ(c.ToString(), "0");
  c = zero % (-b);
  EXPECT_EQ(c.ToString(), "0");
}

TEST_P(BigIntArithTest, ModExact) {
  BigInt a("100000000000", 10, lib_);
  BigInt b("1000000", 10, lib_);
  auto c = a % b;
  EXPECT_TRUE(c.IsZero());

  c = a % (-b);
  EXPECT_TRUE(c.IsZero());

  c = (-a) % b;
  EXPECT_TRUE(c.IsZero());

  c = (-a) % (-b);
  EXPECT_TRUE(c.IsZero());
}

TEST_P(BigIntArithTest, ModAssign) {
  BigInt a("123456789012345678901234567890", 10, lib_);
  BigInt b("9876543210987654321", 10, lib_);
  BigInt zero(0, lib_);

  auto c = a;
  c %= b;
  EXPECT_EQ(c.ToString(), "925925941327160484");

  c = a;
  c %= (-b);
  EXPECT_EQ(c.ToString(), "-8950617269660493837");

  c = -a;
  c %= b;
  EXPECT_EQ(c.ToString(), "8950617269660493837");

  c = -a;
  c %= (-b);
  EXPECT_EQ(c.ToString(), "-925925941327160484");

  c = a;
  c %= BigInt("1234567890", 10, lib_);
  EXPECT_EQ(c.ToString(), "0");

  zero %= b;
  EXPECT_EQ(zero.ToString(), "0");
  zero %= (-b);
  EXPECT_EQ(zero.ToString(), "0");
}

TEST_P(BigIntArithTest, ModAssignExact) {
  BigInt a("100000000000", 10, lib_);
  BigInt b("1000000", 10, lib_);
  BigInt zero(0, lib_);

  auto c = a;
  c %= b;
  EXPECT_TRUE(c.IsZero());

  c = a;
  c %= (-b);
  EXPECT_TRUE(c.IsZero());

  c = -a;
  c %= b;
  EXPECT_TRUE(c.IsZero());

  c = -a;
  c %= (-b);
  EXPECT_TRUE(c.IsZero());

  c = a;
  c %= BigInt("1000000", 10, lib_);
  EXPECT_TRUE(c.IsZero());
}

TEST_P(BigIntArithTest, ModUint64) {
  BigInt a("123456789012345678901234567890", 10, lib_);
  BigInt zero(0, lib_);

  uint64_t c = a % 987654321UL;
  EXPECT_EQ(c, 574845669UL);

  c = (-a) % 987654321UL;
  EXPECT_EQ(c, 412808652UL);

  c = a % 1152921504606846999UL;
  EXPECT_EQ(c, 248787255676114974UL);

  c = (-a) % 1152921504606846999UL;
  EXPECT_EQ(c, 904134248930732025);

  c = zero % 987654321UL;
  EXPECT_EQ(c, 0);
  c = zero % 1152921504606846999UL;
  EXPECT_EQ(c, 0);
}

TEST_P(BigIntArithTest, ModUint64Exact) {
  BigInt a("100000000000", 10, lib_);

  uint64_t c = a % 1000000UL;
  EXPECT_EQ(c, 0);

  c = (-a) % 1000000UL;
  EXPECT_EQ(c, 0);
}

TEST_P(BigIntArithTest, Increment) {
  BigInt a("123456789012345678901234567890", 10, lib_);
  BigInt b = a++;
  EXPECT_EQ(a.ToString(), "123456789012345678901234567891");
  EXPECT_EQ(b.ToString(), "123456789012345678901234567890");

  BigInt c = ++a;
  EXPECT_EQ(a.ToString(), "123456789012345678901234567892");
  EXPECT_EQ(c.ToString(), "123456789012345678901234567892");
}

TEST_P(BigIntArithTest, Decrement) {
  BigInt a("123456789012345678901234567890", 10, lib_);
  BigInt b = a--;
  EXPECT_EQ(a.ToString(), "123456789012345678901234567889");
  EXPECT_EQ(b.ToString(), "123456789012345678901234567890");

  BigInt c = --a;
  EXPECT_EQ(a.ToString(), "123456789012345678901234567888");
  EXPECT_EQ(c.ToString(), "123456789012345678901234567888");
}

TEST_P(BigIntArithTest, Negative) {
  BigInt a("123456789012345678901234567890", 10, lib_);
  EXPECT_EQ((-a).ToString(), "-123456789012345678901234567890");

  BigInt b("0", 10, lib_);
  EXPECT_EQ((-b).ToString(), "0");

  a.NegateInplace();
  EXPECT_EQ(a.ToString(), "-123456789012345678901234567890");
  a.NegateInplace();
  EXPECT_EQ(a.ToString(), "123456789012345678901234567890");
}

TEST_P(BigIntArithTest, Pow) {
  {
    BigInt a("123456789", 10, lib_);
    BigInt b = a.Pow(3);
    EXPECT_EQ(b.ToString(), "1881676371789154860897069");
  }
  {
    BigInt a("-987654321", 10, lib_);
    BigInt b = a.Pow(3);
    EXPECT_EQ(b.ToString(), "-963418328693495609108518161");
  }
  {
    BigInt a("123456789", 10, lib_);
    a.PowInplace(3);
    EXPECT_EQ(a.ToString(), "1881676371789154860897069");
  }
  {
    BigInt a("-987654321", 10, lib_);
    a.PowInplace(3);
    EXPECT_EQ(a.ToString(), "-963418328693495609108518161");
  }
}

TEST_P(BigIntArithTest, ShiftLeft) {
  {
    BigInt a("12345678901234567890", 10, lib_);
    BigInt b = a << 10;
    EXPECT_EQ(b.ToString(), "12641975194864197519360");
  }
  {
    BigInt a("-12345678901234567890", 10, lib_);
    BigInt b = a << 10;
    EXPECT_EQ(b.ToString(), "-12641975194864197519360");
  }
}

TEST_P(BigIntArithTest, ShiftRight) {
  {
    BigInt a("12345678901234567890", 10, lib_);
    BigInt b = a >> 10;
    EXPECT_EQ(b.ToString(), "12056327051986882");
  }
  {
    BigInt a("-12345678901234567890", 10, lib_);
    BigInt b = a >> 10;
    EXPECT_EQ(b.ToString(), "-12056327051986882");
  }
}

TEST_P(BigIntArithTest, BitwiseAnd) {
  {
    BigInt a("0", 10, lib_);
    BigInt b("0", 10, lib_);
    auto c = a & b;
    EXPECT_EQ(c.ToString(), "0");
  }
  {
    BigInt a("0", 10, lib_);
    BigInt b("1", 10, lib_);
    auto c = a & b;
    EXPECT_EQ(c.ToString(), "0");
  }
  {
    BigInt a("-1", 10, lib_);
    BigInt b("1", 10, lib_);
    auto c = a & b;
    EXPECT_EQ(c.ToString(), "1");
  }
  {
    BigInt a("12345678901234567890", 10, lib_);
    BigInt b("9876543210987654321", 10, lib_);
    auto c = a & b;
    EXPECT_EQ(c.ToString(), "9876536407748970640");
  }
  {
    BigInt a("-12345678901234567890", 10, lib_);
    BigInt b("9876543210987654321", 10, lib_);
    auto c = a & b;
    EXPECT_EQ(c.ToString(), "6803238683680");
  }
  {
    BigInt a("-12345678901234567890", 10, lib_);
    BigInt b("-9876543210987654321", 10, lib_);
    auto c = a & b;
    EXPECT_EQ(c.ToString(), "-12345685704473251570");
  }
}

TEST_P(BigIntArithTest, BitwiseIor) {
  {
    BigInt a("0", 10, lib_);
    BigInt b("0", 10, lib_);
    auto c = a | b;
    EXPECT_EQ(c.ToString(), "0");
  }
  {
    BigInt a("0", 10, lib_);
    BigInt b("1", 10, lib_);
    auto c = a | b;
    EXPECT_EQ(c.ToString(), "1");
  }
  {
    BigInt a("-1", 10, lib_);
    BigInt b("1", 10, lib_);
    auto c = a | b;
    EXPECT_EQ(c.ToString(), "-1");
  }
  {
    BigInt a("12345678901234567890", 10, lib_);
    BigInt b("9876543210987654321", 10, lib_);
    auto c = a | b;
    EXPECT_EQ(c.ToString(), "12345685704473251571");
  }
  {
    BigInt a("-12345678901234567890", 10, lib_);
    BigInt b("9876543210987654321", 10, lib_);
    auto c = a | b;
    EXPECT_EQ(c.ToString(), "-2469142493485597249");
  }
  {
    {
      BigInt a("-12345678901234567890", 10, lib_);
      BigInt b("-9876543210987654321", 10, lib_);
      auto c = a | b;
      EXPECT_EQ(c.ToString(), "-9876536407748970641");
    }
  }
}

TEST_P(BigIntArithTest, BitwiseXor) {
  {
    BigInt a("0", 10, lib_);
    BigInt b("0", 10, lib_);
    auto c = a ^ b;
    EXPECT_EQ(c.ToString(), "0");
  }
  {
    BigInt a("0", 10, lib_);
    BigInt b("1", 10, lib_);
    auto c = a ^ b;
    EXPECT_EQ(c.ToString(), "1");
  }
  {
    BigInt a("-1", 10, lib_);
    BigInt b("1", 10, lib_);
    auto c = a ^ b;
    EXPECT_EQ(c.ToString(), "-2");
  }
  {
    BigInt a("12345678901234567890", 10, lib_);
    BigInt b("9876543210987654321", 10, lib_);
    auto c = a ^ b;
    EXPECT_EQ(c.ToString(), "2469149296724280931");
  }
  {
    BigInt a("-12345678901234567890", 10, lib_);
    BigInt b("9876543210987654321", 10, lib_);
    auto c = a ^ b;
    EXPECT_EQ(c.ToString(), "-2469149296724280929");
  }
  {
    {
      BigInt a("-12345678901234567890", 10, lib_);
      BigInt b("-9876543210987654321", 10, lib_);
      auto c = a ^ b;
      EXPECT_EQ(c.ToString(), "2469149296724280929");
    }
  }
}

TEST_P(BigIntArithTest, Compare) {
  BigInt a("123456789012345678901234567890", 10, lib_);
  BigInt b("-987654321098765432109876543210", 10, lib_);

  EXPECT_TRUE(a > b);
  EXPECT_TRUE(b < a);
  EXPECT_TRUE(a >= b);
  EXPECT_TRUE(b <= a);
  EXPECT_TRUE(a != b);
  EXPECT_TRUE(b == b);
}

TEST_P(BigIntArithTest, CompareUint) {
  BigInt a("1234567890123456789", 10, lib_);

  EXPECT_TRUE(a > 1234567890123456788UL);
  EXPECT_TRUE(a < 1234567890123456790UL);
  EXPECT_TRUE(a >= 1234567890123456788UL);
  EXPECT_TRUE(a <= 1234567890123456799UL);
  EXPECT_TRUE(a != 1234567890123456788UL);
  EXPECT_TRUE(a == 1234567890123456789UL);
}

TEST_P(BigIntArithTest, CompareInt) {
  BigInt a("-1234567890123456789", 10, lib_);

  EXPECT_TRUE(a < -1234567890123456788L);
  EXPECT_TRUE(a > -1234567890123456790L);
  EXPECT_TRUE(a <= -1234567890123456788L);
  EXPECT_TRUE(a >= -1234567890123456799L);
  EXPECT_TRUE(a != -1234567890123456788L);
  EXPECT_TRUE(a == -1234567890123456789L);
}

TEST_P(BigIntArithTest, CompareAbs) {
  BigInt a("123456789012345678901234567890", 10, lib_);
  BigInt b("-987654321098765432109876543210", 10, lib_);

  EXPECT_LT(a.CompareAbs(b), 0);
  EXPECT_GT(b.CompareAbs(a), 0);
  EXPECT_EQ(a.CompareAbs(a), 0);
  EXPECT_EQ(b.CompareAbs(b), 0);
}

TEST_P(BigIntArithTest, AddMod) {
  BigInt a("123456789012345678901234567890", 10, lib_);
  BigInt b("987654321098765432109876543210", 10, lib_);
  BigInt m("100000000000000007", 10, lib_);

  auto c = a.AddMod(b, m);
  EXPECT_EQ(c.ToString(), "11033233333403323");
}

TEST_P(BigIntArithTest, SubMod) {
  BigInt a("123456789012345678901234567890", 10, lib_);
  BigInt b("987654321098765432109876543210", 10, lib_);
  BigInt m("100000000000000007", 10, lib_);

  auto c = a.SubMod(b, m);
  EXPECT_EQ(c.ToString(), "80307285185270735");
}

TEST_P(BigIntArithTest, MulMod) {
  BigInt a("123456789012345678901234567890", 10, lib_);
  BigInt b("987654321098765432109876543210", 10, lib_);
  BigInt m("100000000000000007", 10, lib_);

  auto c = a.MulMod(b, m);
  EXPECT_EQ(c.ToString(), "43854261415684461");
}

TEST_P(BigIntArithTest, InvMod) {
  BigInt a("123456789012345678901234567890", 10, lib_);
  BigInt m("100000000000000007", 10, lib_);

  auto c = a.InvMod(m);
  EXPECT_EQ(c.ToString(), "5422927116116793");
}

TEST_P(BigIntArithTest, PowMod) {
  {
    BigInt a("123456789012345678901234567890", 10, lib_);
    BigInt b("987654321098765432109876543210", 10, lib_);
    BigInt m("100000000000000007", 10, lib_);

    auto c = a.PowMod(b, m);
    EXPECT_EQ(c.ToString(), "41322939477322556");
  }
  {
    BigInt a("123456789012345678901234567890", 10, lib_);
    BigInt b("987654321098765432109876543210", 10, lib_);
    BigInt m("100000000000000008", 10, lib_);

    auto c = a.PowMod(b, m);
    EXPECT_EQ(c.ToString(), "54788559872566752");
  }
  {
    BigInt a("123456789012345678901234567890", 10, lib_);
    BigInt b("-987654321098765432109876543210", 10, lib_);
    BigInt m("100000000000000007", 10, lib_);

    auto c = a.PowMod(b, m);
    EXPECT_EQ(c.ToString(), "40266466269607968");
  }
}

TEST_P(BigIntArithTest, Gcd) {
  BigInt a("1234567890", 10, lib_);
  BigInt b("9876543210", 10, lib_);

  BigInt c = a.Gcd(b);
  EXPECT_EQ(c.ToString(), "90");
}

TEST_P(BigIntArithTest, Lcm) {
  BigInt a("1234567890", 10, lib_);
  BigInt b("9876543210", 10, lib_);

  BigInt c = a.Lcm(b);
  EXPECT_EQ(c.ToString(), "135480701236261410");
}

TEST_P(BigIntArithTest, BitCount) {
  BigInt a("123456789012345678901234567890", 10, lib_);
  EXPECT_EQ(a.BitCount(), 97);

  BigInt b("-98765432109876543210987654", 10, lib_);
  EXPECT_EQ(b.BitCount(), 87);

  EXPECT_EQ(BigInt("0", 10, lib_).BitCount(), 0);
  EXPECT_EQ(BigInt("-1", 10, lib_).BitCount(), 1);
  EXPECT_EQ(BigInt("ffffffffffffffff", 16, lib_).BitCount(), 64);
}

TEST_P(BigIntArithTest, Abs) {
  BigInt a("1234567890", 10, lib_);
  EXPECT_EQ(a.Abs().ToString(), "1234567890");

  BigInt b("-9876543210", 10, lib_);
  EXPECT_EQ(b.Abs().ToString(), "9876543210");

  BigInt c("0", 10, lib_);
  EXPECT_EQ(c.Abs().ToString(), "0");
}

TEST_P(BigIntArithTest, IsNegative) {
  EXPECT_FALSE(BigInt("1234567890", 10, lib_).IsNegative());
  EXPECT_TRUE(BigInt("-9876543210", 10, lib_).IsNegative());
  EXPECT_FALSE(BigInt("0", 10, lib_).IsNegative());
}

TEST_P(BigIntArithTest, IsZero) {
  EXPECT_TRUE(BigInt("0", 10, lib_).IsZero());
  EXPECT_FALSE(BigInt("1", 10, lib_).IsZero());
  EXPECT_FALSE(BigInt("-1", 10, lib_).IsZero());
}

TEST_P(BigIntArithTest, IsOdd) {
  EXPECT_FALSE(BigInt("1234567890", 10, lib_).IsOdd());
  EXPECT_TRUE(BigInt("1234567891", 10, lib_).IsOdd());
  EXPECT_FALSE(BigInt("0", 10, lib_).IsOdd());
}

TEST_P(BigIntArithTest, IsPrime) {
  EXPECT_FALSE(BigInt("-1", 10, lib_).IsPrime());
  EXPECT_FALSE(BigInt("0", 10, lib_).IsPrime());
  EXPECT_FALSE(BigInt("1", 10, lib_).IsPrime());
  EXPECT_TRUE(BigInt("2", 10, lib_).IsPrime());
  EXPECT_TRUE(BigInt("3", 10, lib_).IsPrime());
  EXPECT_TRUE(BigInt("13", 10, lib_).IsPrime());
  EXPECT_TRUE(BigInt("23333", 10, lib_).IsPrime());
  EXPECT_FALSE(BigInt("2333333", 10, lib_).IsPrime());
  EXPECT_TRUE(BigInt("6700417", 10, lib_).IsPrime());
  EXPECT_TRUE(BigInt("67280421310721", 10, lib_).IsPrime());
  EXPECT_FALSE(BigInt("672804213107721", 10, lib_).IsPrime());
}

TEST_P(BigIntArithTest, RandomLtN) {
  std::array strs = {"1", "10", "10000", "1234567890"};
  for (auto& str : strs) {
    BigInt n(str, 10, lib_);
    BigInt r = BigInt::RandomLtN(n);
    EXPECT_GE(r, 0);
    EXPECT_LT(r, n);
  }
}

TEST_P(BigIntArithTest, RandomExactBits) {
  {
    BigInt r = lib_->RandomExactBits(1024);
    EXPECT_FALSE(r.IsNegative());
    EXPECT_LE(r.BitCount(), 1024);
  }
  {
    BigInt r = lib_->RandomExactBits(2048);
    EXPECT_FALSE(r.IsNegative());
    EXPECT_LE(r.BitCount(), 2048);
  }
}

TEST_P(BigIntArithTest, RandomMonicExactBits) {
  {
    BigInt r = lib_->RandomMonicExactBits(1024);
    EXPECT_FALSE(r.IsNegative());
    EXPECT_EQ(r.BitCount(), 1024);
  }
  {
    BigInt r = lib_->RandomMonicExactBits(2048);
    EXPECT_FALSE(r.IsNegative());
    EXPECT_EQ(r.BitCount(), 2048);
  }
}

TEST_P(BigIntArithTest, RandPrimeOver) {
  {
    BigInt r = lib_->RandPrimeOver(128, PrimeType::Normal);
    EXPECT_TRUE(r.IsPrime());
    EXPECT_EQ(r.BitCount(), 128);
  }
  {
    BigInt r = lib_->RandPrimeOver(128, PrimeType::BBS);
    EXPECT_TRUE(r.IsPrime());
    EXPECT_EQ(r % 4, 3);
    EXPECT_EQ(r.BitCount(), 128);
  }

  if (lib_->GetLibraryName() != "gmp") {
    for (PrimeType type : {PrimeType::Safe, PrimeType::FastSafe}) {
      BigInt r = lib_->RandPrimeOver(128, type);
      EXPECT_TRUE(r.IsPrime());
      EXPECT_TRUE(((r - 1) / 2).IsPrime());
      EXPECT_EQ(r.BitCount(), 128);
    }
  }
}

TEST_P(BigIntArithTest, ToString) {
  {
    BigInt a("-1234", 10, lib_);
    EXPECT_EQ(a.ToString(), "-1234");
    EXPECT_THAT(a.ToHexString(),
                testing::AnyOf("-4d2", "-4D2", "-04d2", "-04D2"));
  }
  {
    BigInt a("1234567890", 10, lib_);
    EXPECT_EQ(a.ToString(), "1234567890");
    EXPECT_THAT(a.ToHexString(), testing::AnyOf("499602d2", "499602D2"));
  }
  {
    BigInt a("-499602d2", 16, lib_);
    EXPECT_EQ(a.ToString(), "-1234567890");
    EXPECT_THAT(a.ToHexString(), testing::AnyOf("-499602d2", "-499602D2"));
  }
}

TEST_P(BigIntArithTest, ToBytes) {
  BigInt a("1234567890", 10, lib_);
  BigInt b("-1234567890", 10, lib_);

  {
    uint8_t buf;
    a.ToBytes(reinterpret_cast<unsigned char*>(&buf), 1, Endian::native);
    EXPECT_EQ(buf, 210);
    b.ToBytes(reinterpret_cast<unsigned char*>(&buf), 1, Endian::native);
    EXPECT_EQ(buf, 46);
  }
  {
    uint8_t buf;
    a.ToBytes(reinterpret_cast<unsigned char*>(&buf), 1, Endian::big);
    EXPECT_EQ(buf, 210);
    b.ToBytes(reinterpret_cast<unsigned char*>(&buf), 1, Endian::big);
    EXPECT_EQ(buf, 46);
  }
  {
    uint16_t buf;
    a.ToBytes(reinterpret_cast<unsigned char*>(&buf), 2, Endian::native);
    EXPECT_EQ(buf, 722);
    b.ToBytes(reinterpret_cast<unsigned char*>(&buf), 2, Endian::native);
    EXPECT_EQ(buf, 64814);
  }
  {
    uint16_t buf;
    a.ToBytes(reinterpret_cast<unsigned char*>(&buf), 2, Endian::big);
    EXPECT_EQ(buf, 53762);
    b.ToBytes(reinterpret_cast<unsigned char*>(&buf), 2, Endian::big);
    EXPECT_EQ(buf, 12029);
  }
  {
    uint32_t buf;
    a.ToBytes(reinterpret_cast<unsigned char*>(&buf), 4, Endian::native);
    EXPECT_EQ(buf, 1234567890);
    b.ToBytes(reinterpret_cast<unsigned char*>(&buf), 4, Endian::native);
    EXPECT_EQ(buf, -1234567890);
  }
  {
    uint64_t buf;
    a.ToBytes(reinterpret_cast<unsigned char*>(&buf), 8, Endian::native);
    EXPECT_EQ(buf, 1234567890);
    b.ToBytes(reinterpret_cast<unsigned char*>(&buf), 8, Endian::native);
    EXPECT_EQ(buf, -1234567890);
  }
  {
    unsigned char buf[5];
    a.ToBytes(buf, 5, Endian::little);
    EXPECT_EQ(buf[0], 0b11010010);
    EXPECT_EQ(buf[1], 0b00000010);
    EXPECT_EQ(buf[2], 0b10010110);
    EXPECT_EQ(buf[3], 0b01001001);
    EXPECT_EQ(buf[4], 0b00000000);
    b.ToBytes(buf, 5, Endian::little);
    EXPECT_EQ(buf[0], 0b00101110);
    EXPECT_EQ(buf[1], 0b11111101);
    EXPECT_EQ(buf[2], 0b01101001);
    EXPECT_EQ(buf[3], 0b10110110);
    EXPECT_EQ(buf[4], 0b11111111);
  }
  {
    unsigned char buf[5];
    a.ToBytes(buf, 5, Endian::big);
    EXPECT_EQ(buf[0], 0b00000000);
    EXPECT_EQ(buf[1], 0b01001001);
    EXPECT_EQ(buf[2], 0b10010110);
    EXPECT_EQ(buf[3], 0b00000010);
    EXPECT_EQ(buf[4], 0b11010010);
    b.ToBytes(buf, 5, Endian::big);
    EXPECT_EQ(buf[0], 0b11111111);
    EXPECT_EQ(buf[1], 0b10110110);
    EXPECT_EQ(buf[2], 0b01101001);
    EXPECT_EQ(buf[3], 0b11111101);
    EXPECT_EQ(buf[4], 0b00101110);
  }
}

TEST_P(BigIntArithTest, ToMagBytes) {
  BigInt a("1234567890", 10, lib_);
  BigInt b("-1234567890", 10, lib_);
  {
    uint32_t buf;
    a.ToMagBytes(reinterpret_cast<unsigned char*>(&buf), 4, Endian::native);
    EXPECT_EQ(buf, 1234567890);
    b.ToMagBytes(reinterpret_cast<unsigned char*>(&buf), 4, Endian::native);
    EXPECT_EQ(buf, 1234567890);
  }

  {
    unsigned char buf[4];
    a.ToMagBytes(buf, 4, Endian::little);
    EXPECT_EQ(buf[0], 0b11010010);
    EXPECT_EQ(buf[1], 0b00000010);
    EXPECT_EQ(buf[2], 0b10010110);
    EXPECT_EQ(buf[3], 0b01001001);
    b.ToMagBytes(buf, 4, Endian::little);
    EXPECT_EQ(buf[0], 0b11010010);
    EXPECT_EQ(buf[1], 0b00000010);
    EXPECT_EQ(buf[2], 0b10010110);
    EXPECT_EQ(buf[3], 0b01001001);
  }
  {
    unsigned char buf[4];
    a.ToMagBytes(buf, 4, Endian::big);
    EXPECT_EQ(buf[0], 0b01001001);
    EXPECT_EQ(buf[1], 0b10010110);
    EXPECT_EQ(buf[2], 0b00000010);
    EXPECT_EQ(buf[3], 0b11010010);
    b.ToMagBytes(buf, 4, Endian::big);
    EXPECT_EQ(buf[0], 0b01001001);
    EXPECT_EQ(buf[1], 0b10010110);
    EXPECT_EQ(buf[2], 0b00000010);
    EXPECT_EQ(buf[3], 0b11010010);
  }
}

TEST_P(BigIntArithTest, FromMagBytes) {
  {
    uint32_t buf = 1234567890;
    BigInt a(lib_);
    a.FromMagBytes(ByteContainerView(&buf, 4), Endian::native);
    EXPECT_EQ(a.ToString(), "1234567890");
  }
  {
    unsigned char buf[4] = {0b11010010, 0b00000010, 0b10010110, 0b01001001};
    BigInt a(lib_);
    a.FromMagBytes(buf, Endian::little);
    EXPECT_EQ(a.ToString(), "1234567890");
    a.FromMagBytes(buf, Endian::big);
    EXPECT_EQ(a.ToString(), "3523384905");
  }
}

TEST_P(BigIntArithTest, GetBit) {
  {
    BigInt a("1234567890", 10, lib_);
    EXPECT_EQ(a.GetBit(0), 0);
    EXPECT_EQ(a.GetBit(1), 1);
    EXPECT_EQ(a.GetBit(2), 0);
    EXPECT_EQ(a.GetBit(3), 0);
    EXPECT_EQ(a.GetBit(4), 1);
    EXPECT_EQ(a.GetBit(5), 0);
    EXPECT_EQ(a.GetBit(6), 1);
    EXPECT_EQ(a.GetBit(7), 1);
    EXPECT_EQ(a.GetBit(30), 1);
    EXPECT_EQ(a.GetBit(32), 0);
    EXPECT_EQ(a.GetBit(63), 0);
    EXPECT_EQ(a.GetBit(127), 0);
  }
  {
    BigInt a("-1234567890", 10, lib_);
    EXPECT_EQ(a.GetBit(0), 0);
    EXPECT_EQ(a.GetBit(1), 1);
    EXPECT_EQ(a.GetBit(2), 0);
    EXPECT_EQ(a.GetBit(3), 0);
    EXPECT_EQ(a.GetBit(4), 1);
    EXPECT_EQ(a.GetBit(5), 0);
    EXPECT_EQ(a.GetBit(6), 1);
    EXPECT_EQ(a.GetBit(7), 1);
    EXPECT_EQ(a.GetBit(30), 1);
    EXPECT_EQ(a.GetBit(32), 0);
    EXPECT_EQ(a.GetBit(63), 0);
    EXPECT_EQ(a.GetBit(127), 0);
  }
}

TEST_P(BigIntArithTest, SetBit) {
  {
    BigInt a("1234567890", 10, lib_);
    a.SetBit(0, 1);
    EXPECT_EQ(a.ToString(), "1234567891");
    a.SetBit(0, 0);
    EXPECT_EQ(a.ToString(), "1234567890");
    a.SetBit(128, 0);
    EXPECT_EQ(a.ToString(), "1234567890");

    a.SetBit(31, 1);
    EXPECT_EQ(a.ToString(), "3382051538");
    a.SetBit(31, 0);
    EXPECT_EQ(a.ToString(), "1234567890");

    a.SetBit(63, 1);
    EXPECT_EQ(a.ToString(), "9223372038089343698");
    a.SetBit(63, 0);
    EXPECT_EQ(a.ToString(), "1234567890");

    a.SetBit(127, 1);
    EXPECT_EQ(a.ToString(), "170141183460469231731687303717118673618");
    a.SetBit(127, 0);
    EXPECT_EQ(a.ToString(), "1234567890");
  }
  {
    BigInt a("-1234567890", 10, lib_);
    a.SetBit(0, 1);
    EXPECT_EQ(a.ToString(), "-1234567891");
    a.SetBit(0, 0);
    EXPECT_EQ(a.ToString(), "-1234567890");

    a.SetBit(31, 1);
    EXPECT_EQ(a.ToString(), "-3382051538");
    a.SetBit(31, 0);
    EXPECT_EQ(a.ToString(), "-1234567890");

    a.SetBit(63, 1);
    EXPECT_EQ(a.ToString(), "-9223372038089343698");
    a.SetBit(63, 0);
    EXPECT_EQ(a.ToString(), "-1234567890");

    a.SetBit(127, 1);
    EXPECT_EQ(a.ToString(), "-170141183460469231731687303717118673618");
    a.SetBit(127, 0);
    EXPECT_EQ(a.ToString(), "-1234567890");
  }
}

static std::vector<std::shared_ptr<IBigIntLib>> GetLibraries() {
  std::vector<std::shared_ptr<IBigIntLib>> libs;
  for (const auto& lib_name : BigIntLibFactory::Instance().ListLibraries("")) {
    libs.push_back(BigIntLibFactory::Instance().Create("", ArgLib = lib_name));
  }
  return libs;
}

TEST_P(BigIntArithTest, Hash) {
  BigInt a("1234567890", 10, lib_);
  BigInt b("1234567890", 10, lib_);
  BigInt c("9876543210", 10, lib_);

  EXPECT_EQ(std::hash<BigInt>{}(a), std::hash<BigInt>{}(b));
  EXPECT_NE(std::hash<BigInt>{}(a), std::hash<BigInt>{}(c));
}

INSTANTIATE_TEST_SUITE_P(BigIntTests, BigIntArithTest,
                         ::testing::ValuesIn(GetLibraries()),
                         [](const auto& info) {
                           return info.param->GetLibraryName();
                         });

class BigIntSerTest
    : public ::testing::TestWithParam<
          std::tuple<std::shared_ptr<IBigIntLib>, std::shared_ptr<IBigIntLib>,
                     std::string_view>> {};

TEST_P(BigIntSerTest, Serialize) {
  std::shared_ptr<IBigIntLib> lib1 = std::get<0>(GetParam());
  std::shared_ptr<IBigIntLib> lib2 = std::get<1>(GetParam());

  BigInt a(std::string(std::get<2>(GetParam())), 10, lib1);
  auto buffer = a.Serialize();
  BigInt b(lib2);
  b.Deserialize(buffer);
  EXPECT_EQ(a.ToString(), b.ToString());
}

static constexpr std::string_view kSerTestCases[] = {
    "0",
    "1",
    "-1",
    "1234567890",
    "-1234567890",
    "10000000000000000",
    "-10000000000000000",
    "18446744073709551615",
    "-18446744073709551615",
    "10086100861008610086100861008610086",
    "-10086100861008610086100861008610086",
};

INSTANTIATE_TEST_SUITE_P(BigIntTests, BigIntSerTest,
                         ::testing::Combine(::testing::ValuesIn(GetLibraries()),
                                            ::testing::ValuesIn(GetLibraries()),
                                            ::testing::ValuesIn(kSerTestCases)),
                         [](const auto& info) {
                           return std::get<0>(info.param)->GetLibraryName() +
                                  "_to_" +
                                  std::get<1>(info.param)->GetLibraryName() +
                                  "_" + std::to_string(info.index);
                         });

class MontgomeryReductionTest
    : public ::testing::TestWithParam<std::tuple<
          std::shared_ptr<IBigIntLib>, std::array<std::string_view, 3>>> {};

TEST_P(MontgomeryReductionTest, Reduction) {
  std::shared_ptr<IBigIntLib> lib = std::get<0>(GetParam());
  BigInt a(std::string(std::get<1>(GetParam())[0]), 10, lib);
  BigInt b(std::string(std::get<1>(GetParam())[1]), 10, lib);
  BigInt m(std::string(std::get<1>(GetParam())[2]), 10, lib);
  BigInt c = a.MulMod(b, m);

  auto mont_space = lib->CreateMontgomerySpace(m);
  BigInt a_mont = a;
  BigInt b_mont = b;
  mont_space->MapIntoMSpace(a_mont);
  mont_space->MapIntoMSpace(b_mont);
  BigInt c_mont = mont_space->MulMod(a_mont, b_mont);
  mont_space->MapBackToZSpace(c_mont);

  EXPECT_EQ(c, c_mont);
}

static constexpr std::array<std::string_view, 3> kMontREDCTestCases[] = {
    {"0", "100", "98765432109"},
    {"1", "101", "98765432109"},
    {"987654321098", "10086", "12345678901234567890123456789"},
    {"987654321098", "-10086", "12345678901234567890123456789"},
    {"123456789012", "10010", "98765432109876543210987654321"},
    {"-123456789012", "10010", "98765432109876543210987654321"},
    {"-12345678901234567890123456789", "-3432343545673423556098714",
     "98765432109876543210987654321"},
};

INSTANTIATE_TEST_SUITE_P(
    MontgomeryReductionTests, MontgomeryReductionTest,
    ::testing::Combine(::testing::ValuesIn(GetLibraries()),
                       ::testing::ValuesIn(kMontREDCTestCases)),
    [](const auto& info) {
      return std::get<0>(info.param)->GetLibraryName() + "_" +
             std::to_string(info.index);
    });

class MontgomerySpaceTest
    : public ::testing::TestWithParam<std::tuple<
          std::shared_ptr<IBigIntLib>, std::array<std::string_view, 4>>> {};

TEST_P(MontgomerySpaceTest, PowMod) {
  auto lib = std::get<0>(GetParam());
  BigInt a(std::string(std::get<1>(GetParam())[0]), 10, lib);
  BigInt b(std::string(std::get<1>(GetParam())[1]), 10, lib);
  BigInt m(std::string(std::get<1>(GetParam())[2]), 10, lib);
  BigInt r(std::string(std::get<1>(GetParam())[3]), 10, lib);
  auto mont_space = lib->CreateMontgomerySpace(m);

  for (size_t exp_unit_size = 1; exp_unit_size < 18; ++exp_unit_size) {
    BaseTable table;
    mont_space->MakeBaseTable(a, exp_unit_size, b.BitCount(), &table);
    EXPECT_GE(table.exp_max_bits, b.BitCount());

    BigInt v = mont_space->PowMod(table, b);
    mont_space->MapBackToZSpace(v);
    EXPECT_EQ(v, r);
  }
}

static constexpr std::array<std::string_view, 4> kMontPowModTestCases[] = {
    {"0", "1", "1", "0"},
    {"1", "2", "1", "0"},
    {"1", "1", "1", "0"},
    {"2", "12", "123", "37"},
    {"8", "1234", "1234567", "343599"},
    {"1234567", "64", "12345", "9061"},
    {"1234567891011", "1234567891011", "3", "0"},
    {"12345678910111213", "12345678910111213", "12345678910111213", "0"},
    {"12345678901234567890123456789", "11223344556677889112233",
     "123123123123123123123123123123", "107001382026916354418907851658"},
    {"100100100100100100100100100100100100100100100",
     "110110110110110110110110110110110110110110110",
     "10086100186100861100861100861100861100861100861100861100861",
     "5316125410755576553962181190686474428180908106852108883215"},
};

INSTANTIATE_TEST_SUITE_P(
    MontgomerySpaceTests, MontgomerySpaceTest,
    ::testing::Combine(::testing::ValuesIn(GetLibraries()),
                       ::testing::ValuesIn(kMontPowModTestCases)),
    [](const auto& info) {
      return std::get<0>(info.param)->GetLibraryName() + "_" +
             std::to_string(info.index);
    });

}  // namespace yacl::math::test
