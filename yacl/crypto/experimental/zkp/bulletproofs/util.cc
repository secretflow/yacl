// Copyright 2025 @yangjucai.
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

#include "yacl/crypto/experimental/zkp/bulletproofs/util.h"

#include <climits>

#include "yacl/base/exception.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/math/mpint/mp_int.h"

namespace examples::zkp {

//-------------------- Poly2 Implementation --------------------

Poly2::Poly2(yacl::math::MPInt t0_val, yacl::math::MPInt t1_val,
             yacl::math::MPInt t2_val)
    : t0(std::move(t0_val)), t1(std::move(t1_val)), t2(std::move(t2_val)) {}

Poly2::Poly2() : t0(0), t1(0), t2(0) {}

yacl::math::MPInt Poly2::Eval(
    const yacl::math::MPInt& x,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve) const {
  YACL_ENFORCE(curve != nullptr, "Curve cannot be null");
  const auto& order = curve->GetOrder();
  yacl::math::MPInt x_sq = x.MulMod(x, order);
  yacl::math::MPInt term2 = t2.MulMod(x_sq, order);
  yacl::math::MPInt term1 = t1.MulMod(x, order);
  yacl::math::MPInt result = t0.AddMod(term1, order);
  result = result.AddMod(term2, order);
  return result;
}

//-------------------- VecPoly1 Implementation --------------------

VecPoly1::VecPoly1(std::vector<yacl::math::MPInt> v0,
                   std::vector<yacl::math::MPInt> v1)
    : vec0(std::move(v0)), vec1(std::move(v1)) {
  YACL_ENFORCE(vec0.size() == vec1.size(),
               "VecPoly1 vectors must have the same size");
}

// Static factory method
VecPoly1 VecPoly1::Zero(size_t n) {
  std::vector<yacl::math::MPInt> vec0(n, yacl::math::MPInt(0));
  std::vector<yacl::math::MPInt> vec1(n, yacl::math::MPInt(0));
  return VecPoly1(std::move(vec0), std::move(vec1));
}

Poly2 VecPoly1::InnerProduct(
    const VecPoly1& rhs,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve) const {
  YACL_ENFORCE(curve != nullptr, "Curve cannot be null");
  YACL_ENFORCE(this->vec0.size() == rhs.vec0.size(),
               "VecPoly1 inner product requires vectors of the same size");

  // t0 = <vec0, rhs.vec0> mod order
  yacl::math::MPInt t0 =
      examples::zkp::InnerProduct(this->vec0, rhs.vec0, curve);

  // t2 = <vec1, rhs.vec1> mod order
  yacl::math::MPInt t2 =
      examples::zkp::InnerProduct(this->vec1, rhs.vec1, curve);

  // Calculate intermediate sums needed for t1 calculation
  std::vector<yacl::math::MPInt> l0_plus_l1 =
      examples::zkp::AddVec(this->vec0, this->vec1, curve);
  std::vector<yacl::math::MPInt> r0_plus_r1 =
      examples::zkp::AddVec(rhs.vec0, rhs.vec1, curve);

  // t1 = <l0+l1, r0+r1> - t0 - t2 mod order
  yacl::math::MPInt inner_sum =
      examples::zkp::InnerProduct(l0_plus_l1, r0_plus_r1, curve);
  yacl::math::MPInt t1 = inner_sum.SubMod(t0, curve->GetOrder());
  t1 = t1.SubMod(t2, curve->GetOrder());

  return Poly2(t0, t1, t2);
}

std::vector<yacl::math::MPInt> VecPoly1::Eval(
    const yacl::math::MPInt& x,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve) const {
  YACL_ENFORCE(curve != nullptr, "Curve cannot be null");
  size_t n = vec0.size();
  std::vector<yacl::math::MPInt> out(n);

  for (size_t i = 0; i < n; ++i) {
    yacl::math::MPInt term1 = vec1[i].MulMod(x, curve->GetOrder());
    out[i] = vec0[i].AddMod(term1, curve->GetOrder());
  }

  return out;
}

VecPoly1::~VecPoly1() {}  // Destructor body can be empty

//----------------------------------------
// Standalone Utility Functions Implementation
//----------------------------------------

yacl::math::MPInt InnerProduct(
    absl::Span<const yacl::math::MPInt> a,
    absl::Span<const yacl::math::MPInt> b,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve) {
  YACL_ENFORCE(curve != nullptr, "Curve cannot be null");
  YACL_ENFORCE(a.size() == b.size(),
               "Vector sizes don't match for inner product");

  yacl::math::MPInt result(0);
  if (a.empty()) {
    return result;
  }

  const auto& order = curve->GetOrder();
  for (size_t i = 0; i < a.size(); ++i) {
    yacl::math::MPInt term = a[i].MulMod(b[i], order);
    result = result.AddMod(term, order);
  }
  return result;
}

std::vector<yacl::math::MPInt> AddVec(
    const std::vector<yacl::math::MPInt>& a,
    const std::vector<yacl::math::MPInt>& b,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve) {
  YACL_ENFORCE(curve != nullptr, "Curve cannot be null");
  YACL_ENFORCE(a.size() == b.size(),
               "Vector sizes don't match for vector addition");

  std::vector<yacl::math::MPInt> out(a.size());
  const auto& order = curve->GetOrder();
  for (size_t i = 0; i < a.size(); ++i) {
    out[i] = a[i].AddMod(b[i], order);
  }
  return out;
}

std::vector<yacl::math::MPInt> ExpIterVector(
    const yacl::math::MPInt& base, size_t n,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve) {
  YACL_ENFORCE(curve != nullptr, "Curve cannot be null");
  std::vector<yacl::math::MPInt> result;
  if (n == 0) {
    return result;
  }
  result.reserve(n);

  yacl::math::MPInt current(1);
  const auto& order = curve->GetOrder();
  for (size_t i = 0; i < n; ++i) {
    result.emplace_back(current);
    current = current.MulMod(base, order);
  }

  return result;
}

yacl::math::MPInt SumOfPowers(
    const yacl::math::MPInt& base, size_t n,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve) {
  YACL_ENFORCE(curve != nullptr, "Curve cannot be null");
  if (n == 0) {
    return yacl::math::MPInt(0);
  }

  const auto& order = curve->GetOrder();
  yacl::math::MPInt one(1);

  if (base.Mod(order) == one) {
    yacl::math::MPInt n_mp(n);
    return n_mp.Mod(order);
  }

  yacl::math::MPInt base_pow_n = ScalarExp(base, n, curve);
  yacl::math::MPInt numerator = base_pow_n.SubMod(one, order);
  yacl::math::MPInt denominator = base.SubMod(one, order);
  yacl::math::MPInt inv_denominator = denominator.InvertMod(order);

  return numerator.MulMod(inv_denominator, order);
}

yacl::math::MPInt ScalarExp(
    const yacl::math::MPInt& base, size_t exp,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve) {
  YACL_ENFORCE(curve != nullptr, "Curve cannot be null");
  yacl::math::MPInt exp_mp(exp);
  return base.PowMod(exp_mp, curve->GetOrder());
}

yacl::crypto::EcPoint MultiScalarMul(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    const std::vector<yacl::math::MPInt>& scalars,
    const std::vector<yacl::crypto::EcPoint>& points) {
  YACL_ENFORCE(scalars.size() == points.size(),
               "Mismatched vector lengths in multiscalar mul");
  if (scalars.empty()) {
    // Return identity element if vectors are empty
    return curve->MulBase(yacl::math::MPInt(0));
  }

  // Consider using curve->MultiScalarMul(points, scalars) if available in YACL
  // Naive implementation:
  yacl::crypto::EcPoint result =
      curve->MulBase(yacl::math::MPInt(0));  // Start with identity
  for (size_t i = 0; i < scalars.size(); ++i) {
    // Skip multiplication by zero scalar for minor optimization
    if (!scalars[i].IsZero()) {
      yacl::crypto::EcPoint term = curve->Mul(points[i], scalars[i]);
      result = curve->Add(result, term);
    }
  }
  return result;
}

// Helper to create a random MPInt scalar
yacl::math::MPInt CreateRandomScalar(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve) {
  yacl::math::MPInt r;
  r.RandomLtN(curve->GetOrder(), &r);
  return r;
}

size_t NextPowerOfTwo(size_t n) {
  // Handle special case
  if (n == 0) return 1;

  // Check if n is already a power of two
  if ((n & (n - 1)) == 0) {
    return n;
  }

  // Calculate number of leading zeros
  unsigned int leading_zeros;
  if constexpr (sizeof(size_t) == sizeof(unsigned int)) {
    leading_zeros = __builtin_clz(static_cast<unsigned int>(n));
  } else if constexpr (sizeof(size_t) == sizeof(unsigned long)) {
    leading_zeros = __builtin_clzl(static_cast<unsigned long>(n));
  } else {
    leading_zeros = __builtin_clzll(static_cast<unsigned long long>(n));
  }

  // Calculate total bits in size_t
  constexpr int total_bits = sizeof(size_t) * CHAR_BIT;

  // Return 1 shifted left by (total_bits - leading_zeros)
  return size_t(1) << (total_bits - leading_zeros);
}

std::vector<yacl::math::MPInt> VecPoly3::Eval(
    const yacl::math::MPInt& x,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve) const {
  size_t n = T0.size();
  std::vector<yacl::math::MPInt> result(n);
  const auto& order = curve->GetOrder();
  yacl::math::MPInt x_sq = x.MulMod(x, order);
  yacl::math::MPInt x_cb = x_sq.MulMod(x, order);

  for (size_t i = 0; i < n; ++i) {
    auto term1 = T1[i].MulMod(x, order);
    auto term2 = T2[i].MulMod(x_sq, order);
    auto term3 = T3[i].MulMod(x_cb, order);
    result[i] =
        T0[i].AddMod(term1, order).AddMod(term2, order).AddMod(term3, order);
  }
  return result;
}

yacl::math::MPInt Poly6::Eval(
    const yacl::math::MPInt& x,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve) const {
  const auto& order = curve->GetOrder();
  yacl::math::MPInt x_pows[7];
  x_pows[0] = yacl::math::MPInt(1);
  for (int i = 1; i <= 6; ++i) {
    x_pows[i] = x_pows[i - 1].MulMod(x, order);
  }

  yacl::math::MPInt res = T0;
  res = res.AddMod(T1.MulMod(x_pows[1], order), order);
  res = res.AddMod(T2.MulMod(x_pows[2], order), order);
  res = res.AddMod(T3.MulMod(x_pows[3], order), order);
  res = res.AddMod(T4.MulMod(x_pows[4], order), order);
  res = res.AddMod(T5.MulMod(x_pows[5], order), order);
  res = res.AddMod(T6.MulMod(x_pows[6], order), order);
  return res;
}

Poly6 SpecialInnerProduct(const VecPoly3& l, const VecPoly3& r,
                          const std::shared_ptr<yacl::crypto::EcGroup>& curve) {
  Poly6 p;
  p.T0 = InnerProduct(l.T0, r.T0, curve);
  p.T1 = InnerProduct(l.T0, r.T1, curve) + InnerProduct(l.T1, r.T0, curve);
  p.T2 = InnerProduct(l.T0, r.T2, curve) + InnerProduct(l.T1, r.T1, curve) +
         InnerProduct(l.T2, r.T0, curve);
  p.T3 = InnerProduct(l.T0, r.T3, curve) + InnerProduct(l.T1, r.T2, curve) +
         InnerProduct(l.T2, r.T1, curve) + InnerProduct(l.T3, r.T0, curve);
  p.T4 = InnerProduct(l.T1, r.T3, curve) + InnerProduct(l.T2, r.T2, curve) +
         InnerProduct(l.T3, r.T1, curve);
  p.T5 = InnerProduct(l.T2, r.T3, curve) + InnerProduct(l.T3, r.T2, curve);
  p.T6 = InnerProduct(l.T3, r.T3, curve);
  return p;
}

}  // namespace examples::zkp