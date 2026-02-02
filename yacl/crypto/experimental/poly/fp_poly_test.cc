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

#include "yacl/crypto/experimental/poly/fp_poly.h"

#include <utility>

#include "gtest/gtest.h"

namespace yacl::crypto::experimental::poly {
namespace {

TEST(FpPolyTest, AddMulEval) {
  FpContext ctx(97);

  // f(x) = 1 + 2x + 3x^2
  const FpPolynomial f(ctx, {1, 2, 3});
  // g(x) = 5 + x
  const FpPolynomial g(ctx, {5, 1});

  const FpPolynomial sum = f + g;  // 6 + 3x + 3x^2
  ASSERT_EQ(sum.Coeffs().size(), 3);
  EXPECT_EQ(sum.Coeffs()[0].v, 6);
  EXPECT_EQ(sum.Coeffs()[1].v, 3);
  EXPECT_EQ(sum.Coeffs()[2].v, 3);

  const FpPolynomial prod = f * g;  // (1+2x+3x^2)(5+x) = 5 + 11x + 17x^2 + 3x^3
  ASSERT_EQ(prod.Coeffs().size(), 4);
  EXPECT_EQ(prod.Coeffs()[0].v, 5);
  EXPECT_EQ(prod.Coeffs()[1].v, 11);
  EXPECT_EQ(prod.Coeffs()[2].v, 17);
  EXPECT_EQ(prod.Coeffs()[3].v, 3);

  const Fp x = ctx.FromUint64(9);
  const Fp y_f = f.Eval(x);
  const Fp y_g = g.Eval(x);
  const Fp y_prod = prod.Eval(x);
  EXPECT_EQ(y_prod.v, ctx.Mul(y_f, y_g).v);
}

TEST(FpPolyTest, DivRem) {
  FpContext ctx(97);
  // f(x) = x^3 + 2x^2 + 3x + 4
  const FpPolynomial f(ctx, {4, 3, 2, 1});
  // d(x) = x + 5
  const FpPolynomial d(ctx, {5, 1});

  const auto [q, r] = f.DivRem(d);

  // Check: f == q*d + r
  const FpPolynomial recomposed = q.Mul(d).Add(r);
  EXPECT_TRUE(recomposed.Equal(f));

  // deg(r) < deg(d) == 1, so r is constant (or zero)
  EXPECT_LE(r.Degree(), 0);
}

}  // namespace
}  // namespace yacl::crypto::experimental::poly
