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

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

namespace yacl::crypto::experimental::poly {

void FpPolynomial::RequireContext() const {
  YACL_ENFORCE(ctx_ != nullptr, "FpPolynomial: null ctx");
}

void FpPolynomial::RequireCompat(const FpPolynomial& other) const {
  RequireContext();
  other.RequireContext();
  if (ctx_->GetModulus() != other.ctx_->GetModulus()) {
    YACL_THROW_ARGUMENT_ERROR(
        "FpPolynomial: modulus mismatch between polynomials");
  }
}

FpPolynomial::FpPolynomial(const FpContext& ctx) : ctx_(&ctx) {}

FpPolynomial::FpPolynomial(const FpContext& ctx, std::vector<Fp> coeffs)
    : ctx_(&ctx), c_(std::move(coeffs)) {
  // 确保每个系数都在 [0,p)（即使调用者传了非规范值也能工作）
  for (auto& x : c_) {
    x.v %= ctx_->GetModulus();
  }
  Trim();
}

FpPolynomial::FpPolynomial(const FpContext& ctx,
                           std::initializer_list<u64> coeffs_u64)
    : ctx_(&ctx) {
  c_.reserve(coeffs_u64.size());
  for (u64 a : coeffs_u64) {
    c_.push_back(ctx_->FromUint64(a));
  }
  Trim();
}

const FpContext& FpPolynomial::GetContext() const {
  RequireContext();
  return *ctx_;
}

u64 FpPolynomial::GetModulus() const { return GetContext().GetModulus(); }

const std::vector<Fp>& FpPolynomial::Coeffs() const noexcept { return c_; }

std::vector<Fp>& FpPolynomial::Coeffs() noexcept { return c_; }

bool FpPolynomial::IsZero() const noexcept { return c_.empty(); }

std::string FpPolynomial::ToString() const {
  if (IsZero()) {
    return "0";
  }
  std::string out;
  bool first = true;
  for (std::size_t i = 0; i < c_.size(); ++i) {
    const Fp ci = c_[i];
    if (ci.v == 0) {
      continue;
    }
    if (!first) {
      out.append(" + ");
    }
    first = false;
    out.append(std::to_string(ci.v));
    if (i >= 1) {
      out.append("*x");
    }
    if (i >= 2) {
      out.push_back('^');
      out.append(std::to_string(i));
    }
  }
  return out;
}

int FpPolynomial::Degree() const noexcept {
  return c_.empty() ? -1 : static_cast<int>(c_.size()) - 1;
}

void FpPolynomial::Trim() {
  while (!c_.empty() && c_.back().v == 0) {
    c_.pop_back();
  }
}

Fp FpPolynomial::Coeff(size_type i) const noexcept {
  if (i >= c_.size()) {
    return Fp{0};
  }
  return c_[i];
}

Fp FpPolynomial::ConstantTerm() const noexcept {
  return c_.empty() ? Fp{0} : c_[0];
}

Fp FpPolynomial::LeadingCoeff() const {
  if (c_.empty()) {
    YACL_THROW_ARGUMENT_ERROR("FpPolynomial::LeadingCoeff: zero polynomial");
  }
  return c_.back();
}

void FpPolynomial::SetCoeff(size_type i, Fp value) {
  RequireContext();
  value.v %= ctx_->GetModulus();
  if (i >= c_.size()) {
    c_.resize(i + 1, ctx_->Zero());
  }
  c_[i] = value;
  Trim();
}

FpPolynomial FpPolynomial::Add(const FpPolynomial& g) const {
  RequireCompat(g);
  const FpContext& F = *ctx_;

  FpPolynomial r(F);
  const size_type n = std::max(c_.size(), g.c_.size());
  r.c_.assign(n, F.Zero());

  for (size_type i = 0; i < n; ++i) {
    Fp a = (i < c_.size()) ? c_[i] : F.Zero();
    Fp b = (i < g.c_.size()) ? g.c_[i] : F.Zero();
    r.c_[i] = F.Add(a, b);
  }
  r.Trim();
  return r;
}

FpPolynomial FpPolynomial::Sub(const FpPolynomial& g) const {
  RequireCompat(g);
  const FpContext& F = *ctx_;

  FpPolynomial r(F);
  const size_type n = std::max(c_.size(), g.c_.size());
  r.c_.assign(n, F.Zero());

  for (size_type i = 0; i < n; ++i) {
    Fp a = (i < c_.size()) ? c_[i] : F.Zero();
    Fp b = (i < g.c_.size()) ? g.c_[i] : F.Zero();
    r.c_[i] = F.Sub(a, b);
  }
  r.Trim();
  return r;
}

FpPolynomial FpPolynomial::ScalarMul(Fp k) const {
  RequireContext();
  const FpContext& F = *ctx_;
  k.v %= F.GetModulus();

  if (k.v == 0 || IsZero()) {
    return FpPolynomial(F);
  }

  FpPolynomial r(F);
  r.c_.assign(c_.size(), F.Zero());
  for (size_type i = 0; i < c_.size(); ++i) {
    r.c_[i] = F.Mul(c_[i], k);
  }
  r.Trim();
  return r;
}

FpPolynomial FpPolynomial::Derivative() const {
  RequireContext();
  const FpContext& F = *ctx_;

  if (c_.size() <= 1) {
    return FpPolynomial(F);
  }

  FpPolynomial r(F);
  r.c_.assign(c_.size() - 1, F.Zero());

  for (size_type i = 1; i < c_.size(); ++i) {
    // (a_i * i) x^{i-1}
    Fp ii = F.FromUint64(
        static_cast<u64>(i));  // 自动 i mod p（特征 p 的情况也正确）
    r.c_[i - 1] = F.Mul(c_[i], ii);
  }
  r.Trim();
  return r;
}

Fp FpPolynomial::Eval(Fp x) const {
  RequireContext();
  const FpContext& F = *ctx_;
  x.v %= F.GetModulus();

  Fp acc = F.Zero();
  for (size_type i = c_.size(); i-- > 0;) {
    acc = F.Add(F.Mul(acc, x), c_[i]);
  }
  return acc;
}

FpPolynomial FpPolynomial::Neg() const {
  RequireContext();
  const FpContext& F = *ctx_;
  if (IsZero()) {
    return FpPolynomial(F);
  }

  FpPolynomial r(F);
  r.c_.assign(c_.size(), F.Zero());
  for (size_type i = 0; i < c_.size(); ++i) {
    r.c_[i] = F.Neg(c_[i]);
  }
  r.Trim();
  return r;
}

bool FpPolynomial::Equal(const FpPolynomial& g) const noexcept {
  if ((ctx_ == nullptr) || (g.ctx_ == nullptr)) {
    return false;
  }
  if (ctx_->GetModulus() != g.ctx_->GetModulus()) {
    return false;
  }

  size_type na = c_.size();
  while (na > 0 && c_[na - 1].v == 0) {
    --na;
  }

  size_type nb = g.c_.size();
  while (nb > 0 && g.c_[nb - 1].v == 0) {
    --nb;
  }

  if (na != nb) {
    return false;
  }
  for (size_type i = 0; i < na; ++i) {
    if (c_[i].v != g.c_[i].v) {
      return false;
    }
  }
  return true;
}

#ifdef YACL_CRYPTO_EXPERIMENTAL_POLY_ENABLE_OSTREAM
std::ostream& operator<<(std::ostream& os, const FpPolynomial& f) {
  return os << f.ToString();
}
#endif

}  // namespace yacl::crypto::experimental::poly
