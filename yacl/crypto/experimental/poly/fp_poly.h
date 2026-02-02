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

#pragma once

#include <cstddef>
#include <initializer_list>
#include <string>
#include <utility>
#include <vector>

#include "yacl/crypto/experimental/poly/prime_field.h"

#ifdef YACL_CRYPTO_EXPERIMENTAL_POLY_ENABLE_OSTREAM
#include <ostream>
#endif

namespace yacl::crypto::experimental::poly {

// 多项式：c_[i] 是 x^i 的系数，始终保持 Trim 后（最高次系数非 0，除非零多项式）
class FpPolynomial {
 public:
  using size_type = std::size_t;

  // 子乘积树：给 MultiPointEval / interpolation 预留
  struct SubproductTree;

  // ---- constructors ----
  explicit FpPolynomial(const FpContext& ctx);
  FpPolynomial(const FpContext& ctx, std::vector<Fp> coeffs);
  FpPolynomial(const FpContext& ctx, std::initializer_list<u64> coeffs_u64);

  // ---- basic access ----
  const FpContext& GetContext() const;
  u64 GetModulus() const;

  const std::vector<Fp>& Coeffs() const noexcept;
  std::vector<Fp>& Coeffs() noexcept;  // 谨慎使用：改完建议 Trim()

  bool IsZero() const noexcept;

  std::string ToString() const;

  // degree: 零多项式返回 -1
  int Degree() const noexcept;

  // 去掉最高位多余 0
  void Trim();

  // 取第 i 项系数（越界视为 0）
  Fp Coeff(size_type i) const noexcept;

  // 常数项
  Fp ConstantTerm() const noexcept;

  // 最高次系数（零多项式会抛异常）
  Fp LeadingCoeff() const;

  // 设置系数：自动扩容 + 规约 + trim
  void SetCoeff(size_type i, Fp value);

  // ---- poly operations ----
  FpPolynomial Add(const FpPolynomial& g) const;
  FpPolynomial Sub(const FpPolynomial& g) const;
  FpPolynomial Mul(const FpPolynomial& g) const;

  // 标量乘：k * f(x)
  FpPolynomial ScalarMul(Fp k) const;

  // 导数
  FpPolynomial Derivative() const;

  // 单点求值（Horner）
  Fp Eval(Fp x) const;

  // ---- division/remainder ----
  std::pair<FpPolynomial, FpPolynomial> DivRem(
      const FpPolynomial& divisor) const;
  FpPolynomial Mod(const FpPolynomial& divisor) const;

  // ---- convenience operations & operators ----
  FpPolynomial Neg() const;
  bool Equal(const FpPolynomial& g) const noexcept;

  FpPolynomial operator+(const FpPolynomial& g) const { return Add(g); }
  FpPolynomial operator-(const FpPolynomial& g) const { return Sub(g); }
  FpPolynomial operator*(const FpPolynomial& g) const { return Mul(g); }
  FpPolynomial operator-() const { return Neg(); }

  FpPolynomial& operator+=(const FpPolynomial& g) {
    *this = Add(g);
    return *this;
  }
  FpPolynomial& operator-=(const FpPolynomial& g) {
    *this = Sub(g);
    return *this;
  }
  FpPolynomial& operator*=(const FpPolynomial& g) {
    *this = Mul(g);
    return *this;
  }

  // 标量乘
  FpPolynomial operator*(Fp k) const { return ScalarMul(k); }
  FpPolynomial& operator*=(Fp k) {
    *this = ScalarMul(k);
    return *this;
  }
  friend FpPolynomial operator*(Fp k, const FpPolynomial& f) {
    return f.ScalarMul(k);
  }

  // 求值便捷写法：f(x)
  Fp operator()(Fp x) const { return Eval(x); }

  // 逻辑相等
  bool operator==(const FpPolynomial& g) const noexcept { return Equal(g); }
  bool operator!=(const FpPolynomial& g) const noexcept { return !Equal(g); }

  // ---- remainder tree ----
  std::vector<std::vector<FpPolynomial>> RemainderTree(
      const SubproductTree& tree) const;

  // ---- multipoint evaluation ----
  // 朴素多点求值：O(n*deg)
  std::vector<Fp> MultiPointEvalNaive(const std::vector<Fp>& xs) const;

  // 用子乘积树做多点求值
  std::vector<Fp> MultiPointEval(const SubproductTree& tree) const;

  // 便捷：内部建树再求值
  std::vector<Fp> MultiPointEval(const std::vector<Fp>& xs) const;

  // ---- interpolation ----
  // O(n^2) Lagrange 插值：用于基准正确性（可直接用）
  static FpPolynomial InterpolateLagrangeNaive(const FpContext& ctx,
                                               const std::vector<Fp>& xs,
                                               const std::vector<Fp>& ys);

  // 基于子乘积树的插值（正确实现）
  static FpPolynomial InterpolateSubproductTree(const SubproductTree& tree,
                                                const std::vector<Fp>& ys);

 private:
  // ---- fast div/mod helpers (internal) ----
  static FpPolynomial TruncPoly(const FpPolynomial& f, size_type k);
  static FpPolynomial ReversePoly(const FpPolynomial& f, size_type n);
  static FpPolynomial MulTruncPoly(const FpPolynomial& a, const FpPolynomial& b,
                                   size_type k);
  static FpPolynomial InvSeriesPoly(const FpPolynomial& f, size_type k);

  FpPolynomial ModSlowImpl(const FpPolynomial& divisor) const;
  std::pair<FpPolynomial, FpPolynomial> DivRemSlowImpl(
      const FpPolynomial& divisor) const;

  FpPolynomial ModFastImpl(const FpPolynomial& divisor) const;
  std::pair<FpPolynomial, FpPolynomial> DivRemFastImpl(
      const FpPolynomial& divisor) const;

  void RequireContext() const;
  void RequireCompat(const FpPolynomial& other) const;

  const FpContext* ctx_ = nullptr;
  std::vector<Fp> c_;  // coefficients
};

// 子乘积树：levels[0] = (x - x_i)，levels.back()[0] = Π(x - x_i)
struct FpPolynomial::SubproductTree {
  const FpContext* ctx = nullptr;
  std::vector<Fp> points;
  std::vector<std::vector<FpPolynomial>> levels;

  // Cached derivative evaluations
  mutable bool dg_ready = false;
  mutable bool inv_dg_ready = false;
  mutable std::vector<Fp> dg_vals;
  mutable std::vector<Fp> inv_dg_vals;

  SubproductTree() = default;
  explicit SubproductTree(const FpContext& c);

  bool Empty() const noexcept;
  std::size_t NumPoints() const noexcept;
  std::size_t NumLevels() const noexcept;

  const FpPolynomial& Root() const;

  // Ensure dG(x_i) (and optionally its inverse) is computed and cached.
  void EnsureDerivativeVals(bool need_inv) const;

  const std::vector<Fp>& DerivativeVals() const;
  const std::vector<Fp>& InvDerivativeVals() const;

  // 构建子乘积树（正确优先）
  static SubproductTree Build(const FpContext& ctx, const std::vector<Fp>& xs);
};

#ifdef YACL_CRYPTO_EXPERIMENTAL_POLY_ENABLE_OSTREAM
std::ostream& operator<<(std::ostream& os, const FpPolynomial& f);
#endif

}  // namespace yacl::crypto::experimental::poly
