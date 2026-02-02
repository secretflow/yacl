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
#include <utility>
#include <vector>

namespace yacl::crypto::experimental::poly {

std::pair<FpPolynomial, FpPolynomial> FpPolynomial::DivRem(
    const FpPolynomial& divisor) const {
  RequireCompat(divisor);
  const FpContext& F = *ctx_;

  if (divisor.IsZero()) {
    YACL_THROW_ARGUMENT_ERROR(
        "FpPolynomial::DivRem: division by zero polynomial");
  }
  if (this->IsZero()) {
    return {FpPolynomial(F), FpPolynomial(F)};
  }

  const int degA = this->Degree();
  const int degB = divisor.Degree();
  if (degA < degB) {
    return {FpPolynomial(F), *this};
  }
  if (degB == 0) {
    Fp invb = F.Inv(divisor.c_[0]);
    return {this->ScalarMul(invb), FpPolynomial(F)};
  }

  const auto n = static_cast<size_type>(degA + 1);
  const auto m = static_cast<size_type>(degB + 1);

  // 小规模用 slow，常数更低
  if (n <= 512 || m <= 64 || (n - m) <= 64) {
    return DivRemSlowImpl(divisor);
  }
  return DivRemFastImpl(divisor);
}

FpPolynomial FpPolynomial::Mod(const FpPolynomial& divisor) const {
  RequireCompat(divisor);
  const FpContext& F = *ctx_;

  if (divisor.IsZero()) {
    YACL_THROW_ARGUMENT_ERROR("FpPolynomial::Mod: division by zero polynomial");
  }
  if (this->IsZero()) {
    return FpPolynomial(F);
  }

  const int degA = this->Degree();
  const int degB = divisor.Degree();
  if (degA < degB) {
    return *this;
  }
  if (degB == 0) {
    return FpPolynomial(F);
  }

  const auto n = static_cast<size_type>(degA + 1);
  const auto m = static_cast<size_type>(degB + 1);

  if (n <= 512 || m <= 64 || (n - m) <= 64) {
    return ModSlowImpl(divisor);
  }
  return ModFastImpl(divisor);
}

FpPolynomial FpPolynomial::TruncPoly(const FpPolynomial& f, size_type k) {
  f.RequireContext();
  const FpContext& F = *f.ctx_;
  if (k == 0 || f.c_.empty()) {
    return FpPolynomial(F);
  }
  const size_type take = std::min(k, f.c_.size());
  std::vector<Fp> v(take);
  for (size_type i = 0; i < take; ++i) {
    v[i] = f.c_[i];
  }
  return {F, std::move(v)};
}

FpPolynomial FpPolynomial::ReversePoly(const FpPolynomial& f, size_type n) {
  f.RequireContext();
  const FpContext& F = *f.ctx_;
  if (n == 0) {
    return FpPolynomial(F);
  }
  std::vector<Fp> v(n, F.Zero());
  for (size_type i = 0; i < n; ++i) {
    const size_type src = n - 1 - i;
    if (src < f.c_.size()) {
      v[i] = f.c_[src];
    }
  }
  return {F, std::move(v)};
}

FpPolynomial FpPolynomial::InvSeriesPoly(const FpPolynomial& f, size_type k) {
  f.RequireContext();
  const FpContext& F = *f.ctx_;
  if (k == 0) {
    return FpPolynomial(F);
  }
  YACL_ENFORCE(!f.c_.empty() && f.c_[0].v != 0,
               "InvSeriesPoly: f[0] must be non-zero");

  FpPolynomial g(F, {F.Inv(f.c_[0])});

  size_type cur = 1;
  const Fp two = F.FromUint64(2);

  while (cur < k) {
    const size_type nxt = std::min(cur * 2, k);

    FpPolynomial f_tr = TruncPoly(f, nxt);
    FpPolynomial t = MulTruncPoly(f_tr, g, nxt);

    std::vector<Fp> uc(nxt, F.Zero());
    for (size_type i = 0; i < nxt; ++i) {
      Fp ti = (i < t.c_.size()) ? t.c_[i] : F.Zero();
      uc[i] = F.Neg(ti);
    }
    uc[0] = F.Add(uc[0], two);
    FpPolynomial u(F, std::move(uc));

    g = MulTruncPoly(g, u, nxt);
    cur = nxt;
  }

  return TruncPoly(g, k);
}

std::pair<FpPolynomial, FpPolynomial> FpPolynomial::DivRemSlowImpl(
    const FpPolynomial& divisor) const {
  RequireCompat(divisor);
  const FpContext& F = *ctx_;

  YACL_ENFORCE(!divisor.IsZero(), "FpPolynomial::DivRemSlowImpl: div by zero");
  if (this->IsZero()) {
    return {FpPolynomial(F), FpPolynomial(F)};
  }

  const int degA = this->Degree();
  const int degB = divisor.Degree();
  if (degA < degB) {
    return {FpPolynomial(F), *this};
  }

  if (degB == 0) {
    Fp invb = F.Inv(divisor.c_[0]);
    return {this->ScalarMul(invb), FpPolynomial(F)};
  }

  std::vector<Fp> r = c_;
  std::vector<Fp> q(static_cast<size_type>(degA - degB + 1), F.Zero());

  const Fp lcB = divisor.c_.back();
  const bool monic = (lcB.v == 1);
  const Fp inv_lcB = monic ? F.One() : F.Inv(lcB);

  int degR = degA;
  while (degR >= degB) {
    const Fp lead = r[static_cast<size_type>(degR)];
    if (lead.v != 0) {
      const Fp factor = monic ? lead : F.Mul(lead, inv_lcB);
      const int k = degR - degB;
      q[static_cast<size_type>(k)] = factor;

      for (int i = 0; i < degB; ++i) {
        const Fp di = divisor.c_[static_cast<size_type>(i)];
        if (di.v == 0) {
          continue;
        }
        const auto idx = static_cast<size_type>(i + k);
        r[idx] = F.Sub(r[idx], F.Mul(factor, di));
      }
      r[static_cast<size_type>(degR)] = F.Zero();
    } else {
      r[static_cast<size_type>(degR)] = F.Zero();
    }

    --degR;
    while (degR >= 0 && r[static_cast<size_type>(degR)].v == 0) {
      --degR;
    }
  }

  FpPolynomial Q(F, std::move(q));
  if (degR < 0) {
    return {Q, FpPolynomial(F)};
  }

  r.resize(static_cast<size_type>(degR + 1));
  FpPolynomial R(F, std::move(r));
  return {Q, R};
}

FpPolynomial FpPolynomial::ModSlowImpl(const FpPolynomial& divisor) const {
  return DivRemSlowImpl(divisor).second;
}

std::pair<FpPolynomial, FpPolynomial> FpPolynomial::DivRemFastImpl(
    const FpPolynomial& divisor) const {
  RequireCompat(divisor);
  const FpContext& F = *ctx_;

  YACL_ENFORCE(!divisor.IsZero(), "FpPolynomial::DivRemFastImpl: div by zero");
  if (this->IsZero()) {
    return {FpPolynomial(F), FpPolynomial(F)};
  }

  const int degA = this->Degree();
  const int degB = divisor.Degree();
  if (degA < degB) {
    return {FpPolynomial(F), *this};
  }

  if (degB == 0) {
    Fp invb = F.Inv(divisor.c_[0]);
    return {this->ScalarMul(invb), FpPolynomial(F)};
  }

  const auto n = static_cast<size_type>(degA + 1);
  const auto m = static_cast<size_type>(degB + 1);
  const size_type k = n - m + 1;

  FpPolynomial Ar = ReversePoly(*this, n);
  FpPolynomial Br = ReversePoly(divisor, m);

  FpPolynomial Br_inv = InvSeriesPoly(Br, k);

  FpPolynomial Ar_tr = TruncPoly(Ar, k);
  FpPolynomial qrev = MulTruncPoly(Ar_tr, Br_inv, k);

  FpPolynomial q = ReversePoly(qrev, k);
  q.Trim();

  FpPolynomial r = this->Sub(divisor.Mul(q));
  r.Trim();

  return {q, r};
}

FpPolynomial FpPolynomial::ModFastImpl(const FpPolynomial& divisor) const {
  return DivRemFastImpl(divisor).second;
}

}  // namespace yacl::crypto::experimental::poly
