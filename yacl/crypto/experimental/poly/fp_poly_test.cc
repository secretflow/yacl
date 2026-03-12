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

#include <cstddef>
#include <vector>

#include "gtest/gtest.h"

namespace yacl::crypto::experimental::poly {
namespace {

std::vector<Fp> MakeDeterministicCoeffs(const FpContext& ctx, std::size_t size,
                                        u64 seed) {
  std::vector<Fp> coeffs;
  coeffs.reserve(size);

  u64 state = seed;
  for (std::size_t idx = 0; idx < size; ++idx) {
    state = state * 6364136223846793005ULL + 1442695040888963407ULL;
    const u64 mixed =
        state ^ (state >> 29) ^ (0x9E3779B97F4A7C15ULL * (idx + 1));
    coeffs.push_back(ctx.FromUint64(mixed));
  }

  if (!coeffs.empty() && coeffs.back().v == 0) {
    coeffs.back() = ctx.One();
  }
  return coeffs;
}

FpPolynomial NaiveMulPolynomial(const FpPolynomial& lhs,
                                const FpPolynomial& rhs) {
  const FpContext& ctx = lhs.GetContext();
  const auto& lhs_coeffs = lhs.Coeffs();
  const auto& rhs_coeffs = rhs.Coeffs();

  if (lhs_coeffs.empty() || rhs_coeffs.empty()) {
    return FpPolynomial(ctx);
  }

  std::vector<Fp> out(lhs_coeffs.size() + rhs_coeffs.size() - 1, ctx.Zero());
  for (std::size_t lhs_idx = 0; lhs_idx < lhs_coeffs.size(); ++lhs_idx) {
    for (std::size_t rhs_idx = 0; rhs_idx < rhs_coeffs.size(); ++rhs_idx) {
      out[lhs_idx + rhs_idx] =
          ctx.Add(out[lhs_idx + rhs_idx],
                  ctx.Mul(lhs_coeffs[lhs_idx], rhs_coeffs[rhs_idx]));
    }
  }

  return FpPolynomial(ctx, std::move(out));
}

FpPolynomial MakeSparseEndpointPolynomial(const FpContext& ctx,
                                          std::size_t size, u64 constant_coeff,
                                          u64 leading_coeff) {
  std::vector<Fp> coeffs(size, ctx.Zero());
  coeffs[0] = ctx.FromUint64(constant_coeff);
  coeffs[size - 1] = ctx.FromUint64(leading_coeff);
  return FpPolynomial(ctx, std::move(coeffs));
}

void ExpectSamePolynomial(const FpPolynomial& actual,
                          const FpPolynomial& expected) {
  ASSERT_EQ(actual.Coeffs().size(), expected.Coeffs().size());
  for (std::size_t idx = 0; idx < expected.Coeffs().size(); ++idx) {
    EXPECT_EQ(actual.Coeffs()[idx].v, expected.Coeffs()[idx].v)
        << "coefficient mismatch at index " << idx;
  }
}

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

TEST(FpPolyTest, OwnsTemporaryContext) {
  const FpPolynomial f(FpContext(97), {1, 2, 3});
  const FpPolynomial g(FpContext(97), {5, 1});

  EXPECT_EQ(f.GetModulus(), 97);
  EXPECT_EQ(g.GetModulus(), 97);

  const FpPolynomial prod = f * g;
  ASSERT_EQ(prod.Coeffs().size(), 4);
  EXPECT_EQ(prod.Coeffs()[0].v, 5);
  EXPECT_EQ(prod.Coeffs()[1].v, 11);
  EXPECT_EQ(prod.Coeffs()[2].v, 17);
  EXPECT_EQ(prod.Coeffs()[3].v, 3);

  const Fp x = f.GetContext().FromUint64(9);
  EXPECT_EQ(prod.Eval(x).v, f.GetContext().Mul(f.Eval(x), g.Eval(x)).v);
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

TEST(FpPolyTest, SetCoeffsTrimsTrailingZeros) {
  FpContext ctx(97);
  FpPolynomial poly(ctx, {1, 2, 3});

  poly.SetCoeffs(std::vector<Fp>{ctx.FromUint64(5), ctx.Zero(), ctx.Zero()});

  ASSERT_EQ(poly.Coeffs().size(), 1);
  EXPECT_EQ(poly.Coeffs()[0].v, 5);
  EXPECT_EQ(poly.Degree(), 0);
}

TEST(FpPolyTest, MulHandlesZeroAndConstantPolynomials) {
  FpContext ctx(97);

  const FpPolynomial zero(ctx);
  const FpPolynomial constant(ctx, {42});
  const FpPolynomial sparse(ctx, {3, 0, 5});

  ExpectSamePolynomial(zero * sparse, FpPolynomial(ctx));
  ExpectSamePolynomial(constant * sparse, NaiveMulPolynomial(constant, sparse));
}

TEST(FpPolyTest, MulMatchesNaiveOnNarrowNttPath) {
  FpContext ctx(998244353ULL);

  const FpPolynomial lhs(ctx, MakeDeterministicCoeffs(ctx, 129, 1));
  const FpPolynomial rhs(ctx, MakeDeterministicCoeffs(ctx, 140, 2));

  ExpectSamePolynomial(lhs * rhs, NaiveMulPolynomial(lhs, rhs));
}

TEST(FpPolyTest, MulMatchesNaiveNearUint64LimitOnFivePrimePath) {
  constexpr u64 kLargePrime = 18446744073709551557ULL;
  FpContext ctx(kLargePrime);

  const FpPolynomial lhs(ctx, MakeDeterministicCoeffs(ctx, 129, 3));
  const FpPolynomial rhs(ctx, MakeDeterministicCoeffs(ctx, 140, 4));

  ExpectSamePolynomial(lhs * rhs, NaiveMulPolynomial(lhs, rhs));
}

TEST(FpPolyTest, MulMatchesNaiveNearUint64LimitOnWideNttPath) {
  constexpr u64 kLargePrime = 18446744073709551557ULL;
  FpContext ctx(kLargePrime);

  const FpPolynomial lhs(ctx, MakeDeterministicCoeffs(ctx, 2048, 5));
  const FpPolynomial rhs(ctx, MakeDeterministicCoeffs(ctx, 2049, 6));

  ExpectSamePolynomial(lhs * rhs, NaiveMulPolynomial(lhs, rhs));
}

TEST(FpPolyTest, MulSupportsLargeInputWithTwoNarrowPrimes) {
  constexpr u64 kModulus = 65537ULL;
  constexpr std::size_t kLongSize = (1U << 23) - 63;
  constexpr std::size_t kShortSize = 65;

  FpContext ctx(kModulus);
  const FpPolynomial f = MakeSparseEndpointPolynomial(ctx, kLongSize, 7, 11);
  const FpPolynomial g = MakeSparseEndpointPolynomial(ctx, kShortSize, 3, 5);

  const FpPolynomial prod = f * g;
  const std::size_t high_f = kLongSize - 1;
  const std::size_t high_g = kShortSize - 1;

  ASSERT_EQ(prod.Coeffs().size(), kLongSize + kShortSize - 1);
  EXPECT_EQ(prod.Coeff(0).v, 21);
  EXPECT_EQ(prod.Coeff(1).v, 0);
  EXPECT_EQ(prod.Coeff(high_g).v, 35);
  EXPECT_EQ(prod.Coeff(high_g + 1).v, 0);
  EXPECT_EQ(prod.Coeff(high_f).v, 33);
  EXPECT_EQ(prod.Coeff(high_f + high_g).v, 55);
}

TEST(FpPolyTest, MulSupportsLargeInputWithFourNarrowPrimes) {
  constexpr u64 kModulus = 1000000000039ULL;
  constexpr std::size_t kPolySize = (1U << 20) + 1;

  FpContext ctx(kModulus);
  const FpPolynomial f = MakeSparseEndpointPolynomial(ctx, kPolySize, 1, 2);
  const FpPolynomial g = MakeSparseEndpointPolynomial(ctx, kPolySize, 3, 4);

  const FpPolynomial prod = f * g;
  ASSERT_EQ(prod.Coeffs().size(), 2 * kPolySize - 1);
  EXPECT_EQ(prod.Coeff(0).v, 3);
  EXPECT_EQ(prod.Coeff(1).v, 0);
  EXPECT_EQ(prod.Coeff(kPolySize - 1).v, 10);
  EXPECT_EQ(prod.Coeff(kPolySize).v, 0);
  EXPECT_EQ(prod.Coeff(2 * kPolySize - 2).v, 8);
}

}  // namespace
}  // namespace yacl::crypto::experimental::poly
