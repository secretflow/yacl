// Copyright 2026 Ant Group Co., Ltd.
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

#include "yacl/crypto/experimental/poly/prime_field.h"

#include <vector>

#include "gtest/gtest.h"

namespace yacl::crypto::experimental::poly {
namespace {

TEST(PrimeFieldTest, FromIntAndBasicOps) {
  FpContext ctx(97);

  const Fp a = ctx.FromUint64(100);     // 3
  const Fp b = ctx.FromInt64(-2);       // 95
  const Fp c = ctx.FromUint64(97 + 1);  // 1

  EXPECT_EQ(a.v, 3);
  EXPECT_EQ(b.v, 95);
  EXPECT_EQ(c.v, 1);

  EXPECT_EQ(ctx.Add(a, b).v, 1);
  EXPECT_EQ(ctx.Sub(a, b).v, 5);
  EXPECT_EQ(ctx.Neg(a).v, 94);

  EXPECT_EQ(ctx.Mul(a, b).v, (3ULL * 95ULL) % 97ULL);
  EXPECT_EQ(ctx.Sqr(a).v, (3ULL * 3ULL) % 97ULL);

  EXPECT_EQ(ctx.Pow(a, 0).v, 1);
  EXPECT_EQ(ctx.Pow(a, 1).v, 3);
  EXPECT_EQ(ctx.Pow(a, 2).v, 9);
}

TEST(PrimeFieldTest, InvAndDiv) {
  FpContext ctx(97);
  const Fp a = ctx.FromUint64(5);
  const Fp b = ctx.FromUint64(37);

  const Fp binv = ctx.Inv(b);
  EXPECT_EQ(ctx.Mul(b, binv).v, 1);
  EXPECT_EQ(ctx.Div(a, b).v, ctx.Mul(a, binv).v);

  EXPECT_THROW((void)ctx.Inv(ctx.Zero()), ::yacl::EnforceNotMet);
}

TEST(PrimeFieldTest, BatchInv) {
  FpContext ctx(97);
  std::vector<Fp> v = {
      ctx.FromUint64(2),
      ctx.FromUint64(3),
      ctx.FromUint64(5),
      ctx.FromUint64(7),
  };

  std::vector<Fp> orig = v;
  ctx.BatchInv(v);
  ASSERT_EQ(v.size(), orig.size());
  for (size_t i = 0; i < v.size(); ++i) {
    EXPECT_EQ(ctx.Mul(orig[i], v[i]).v, 1);
  }
}

TEST(PrimeFieldTest, MersennePrimeFastPath) {
  // 2^61 - 1 is a Mersenne prime and a realistic 64-bit field modulus.
  constexpr uint64_t p = (1ULL << 61) - 1;
  FpContext ctx(p);
  const Fp a = ctx.FromUint64(p + 123456);
  const Fp b = ctx.FromUint64(p + 654321);

  EXPECT_LT(a.v, p);
  EXPECT_LT(b.v, p);
  EXPECT_EQ(a.v, 123456);
  EXPECT_EQ(b.v, 654321);

  // Cross-check multiplication against the generic (u128 % p) formula.
  const uint64_t expected =
      (static_cast<uint128_t>(a.v) * static_cast<uint128_t>(b.v)) % p;
  EXPECT_EQ(ctx.Mul(a, b).v, expected);
}

}  // namespace
}  // namespace yacl::crypto::experimental::poly
