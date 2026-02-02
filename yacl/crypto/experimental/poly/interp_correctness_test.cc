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

#include <vector>

#include "gtest/gtest.h"

#include "yacl/crypto/experimental/poly/fp_poly.h"

namespace yacl::crypto::experimental::poly {
namespace {

TEST(InterpCorrectnessTest, LagrangeNaiveVsSubproductTree) {
  FpContext ctx(97);

  // Choose distinct points in F_p.
  const std::vector<Fp> xs = {
      ctx.FromUint64(0), ctx.FromUint64(1), ctx.FromUint64(2),
      ctx.FromUint64(3), ctx.FromUint64(4), ctx.FromUint64(5),
      ctx.FromUint64(6), ctx.FromUint64(7),
  };

  // Define y_i = (13*x_i^3 + 7*x_i + 42) mod p.
  std::vector<Fp> ys;
  ys.reserve(xs.size());
  for (const Fp x : xs) {
    Fp acc = ctx.FromUint64(42);
    acc = ctx.Add(acc, ctx.Mul(ctx.FromUint64(7), x));
    acc = ctx.Add(acc, ctx.Mul(ctx.FromUint64(13), ctx.Mul(ctx.Mul(x, x), x)));
    ys.push_back(acc);
  }

  const FpPolynomial f1 = FpPolynomial::InterpolateLagrangeNaive(ctx, xs, ys);
  const auto tree = FpPolynomial::SubproductTree::Build(ctx, xs);
  const FpPolynomial f2 = FpPolynomial::InterpolateSubproductTree(tree, ys);

  EXPECT_TRUE(f1.Equal(f2));

  const auto ys1 = f1.MultiPointEval(xs);
  const auto ys2 = f2.MultiPointEval(xs);
  ASSERT_EQ(ys1.size(), ys.size());
  ASSERT_EQ(ys2.size(), ys.size());
  for (size_t i = 0; i < ys.size(); ++i) {
    EXPECT_EQ(ys1[i].v, ys[i].v);
    EXPECT_EQ(ys2[i].v, ys[i].v);
  }
}

}  // namespace
}  // namespace yacl::crypto::experimental::poly
