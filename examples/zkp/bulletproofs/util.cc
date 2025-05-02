#include "zkp/bulletproofs/util.h"

#include <vector>
#include <memory>
#include <numeric>
#include <algorithm>
#include <cstring>

#include "yacl/base/exception.h"
#include "yacl/math/mpint/mp_int.h"
#include "yacl/crypto/ecc/ecc_spi.h"

namespace examples::zkp {

//-------------------- Poly2 Implementation --------------------

Poly2::Poly2(yacl::math::MPInt t0_val, yacl::math::MPInt t1_val, yacl::math::MPInt t2_val)
    : t0(std::move(t0_val)), t1(std::move(t1_val)), t2(std::move(t2_val)) {}

Poly2::Poly2() : t0(0), t1(0), t2(0) {}

yacl::math::MPInt Poly2::Eval(const yacl::math::MPInt& x,
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

VecPoly1::VecPoly1(std::vector<yacl::math::MPInt> v0, std::vector<yacl::math::MPInt> v1)
    : vec0(std::move(v0)), vec1(std::move(v1)) {
  YACL_ENFORCE(vec0.size() == vec1.size(), "VecPoly1 vectors must have the same size");
}

// Static factory method
VecPoly1 VecPoly1::Zero(size_t n) {
  std::vector<yacl::math::MPInt> vec0(n, yacl::math::MPInt(0));
  std::vector<yacl::math::MPInt> vec1(n, yacl::math::MPInt(0));
  return VecPoly1(std::move(vec0), std::move(vec1));
}

Poly2 VecPoly1::InnerProduct(const VecPoly1& rhs,
                             const std::shared_ptr<yacl::crypto::EcGroup>& curve) const {
  YACL_ENFORCE(curve != nullptr, "Curve cannot be null");
  YACL_ENFORCE(this->vec0.size() == rhs.vec0.size(),
               "VecPoly1 inner product requires vectors of the same size");

  // *** FIX: Use explicit namespace or :: prefix for standalone functions ***
  // t0 = <vec0, rhs.vec0> mod order
  yacl::math::MPInt t0 = examples::zkp::InnerProduct(this->vec0, rhs.vec0, curve);

  // t2 = <vec1, rhs.vec1> mod order
  yacl::math::MPInt t2 = examples::zkp::InnerProduct(this->vec1, rhs.vec1, curve);

  // Calculate intermediate sums needed for t1 calculation
  std::vector<yacl::math::MPInt> l0_plus_l1 = examples::zkp::AddVec(this->vec0, this->vec1, curve);
  std::vector<yacl::math::MPInt> r0_plus_r1 = examples::zkp::AddVec(rhs.vec0, rhs.vec1, curve);

  // t1 = <l0+l1, r0+r1> - t0 - t2 mod order
  yacl::math::MPInt inner_sum = examples::zkp::InnerProduct(l0_plus_l1, r0_plus_r1, curve);
  yacl::math::MPInt t1 = inner_sum.SubMod(t0, curve->GetOrder());
  t1 = t1.SubMod(t2, curve->GetOrder());

  return Poly2(t0, t1, t2);
}

std::vector<yacl::math::MPInt> VecPoly1::Eval(const yacl::math::MPInt& x,
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

VecPoly1::~VecPoly1() {} // Destructor body can be empty

//----------------------------------------
// Standalone Utility Functions Implementation
//----------------------------------------

yacl::math::MPInt InnerProduct(const std::vector<yacl::math::MPInt>& a,
                               const std::vector<yacl::math::MPInt>& b,
                               const std::shared_ptr<yacl::crypto::EcGroup>& curve) {
  YACL_ENFORCE(curve != nullptr, "Curve cannot be null");
  YACL_ENFORCE(a.size() == b.size(), "Vector sizes don't match for inner product");

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

std::vector<yacl::math::MPInt> AddVec(const std::vector<yacl::math::MPInt>& a,
                                      const std::vector<yacl::math::MPInt>& b,
                                      const std::shared_ptr<yacl::crypto::EcGroup>& curve) {
  YACL_ENFORCE(curve != nullptr, "Curve cannot be null");
  YACL_ENFORCE(a.size() == b.size(), "Vector sizes don't match for vector addition");

  std::vector<yacl::math::MPInt> out(a.size());
  const auto& order = curve->GetOrder();
  for (size_t i = 0; i < a.size(); ++i) {
    out[i] = a[i].AddMod(b[i], order);
  }
  return out;
}

std::vector<yacl::math::MPInt> ExpIterVector(const yacl::math::MPInt& base,
                                             size_t n,
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
    result.push_back(current);
    current = current.MulMod(base, order);
  }

  return result;
}

yacl::math::MPInt SumOfPowers(const yacl::math::MPInt& base,
                              size_t n,
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

yacl::math::MPInt ScalarExp(const yacl::math::MPInt& base,
                            size_t exp,
                            const std::shared_ptr<yacl::crypto::EcGroup>& curve) {
  YACL_ENFORCE(curve != nullptr, "Curve cannot be null");
  yacl::math::MPInt exp_mp(exp);
  return base.PowMod(exp_mp, curve->GetOrder());
}

size_t FloorLog2(size_t x) {
  if (x == 0) return 0;
#if defined(__GNUC__) || defined(__clang__)
    return (sizeof(unsigned long long) * 8 - 1) - __builtin_clzll(static_cast<unsigned long long>(x));
#else
    size_t result = 0;
    while (x >>= 1) {
        ++result;
    }
    return result;
#endif
}

yacl::crypto::EcPoint MultiScalarMul(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    const std::vector<yacl::math::MPInt>& scalars,
    const std::vector<yacl::crypto::EcPoint>& points) {

  YACL_ENFORCE(scalars.size() == points.size(), "Mismatched vector lengths in multiscalar mul");
  if (scalars.empty()) {
      // Return identity element if vectors are empty
      return curve->MulBase(yacl::math::MPInt(0));
  }

  // Consider using curve->MultiScalarMul(points, scalars) if available in YACL
  // Naive implementation:
  yacl::crypto::EcPoint result = curve->MulBase(yacl::math::MPInt(0)); // Start with identity
  for (size_t i = 0; i < scalars.size(); ++i) {
    // Skip multiplication by zero scalar for minor optimization
    if (!scalars[i].IsZero()) {
        yacl::crypto::EcPoint term = curve->Mul(points[i], scalars[i]);
        result = curve->Add(result, term);
    }
  }
  return result;
}

// Helper to create a dummy EcPoint
yacl::crypto::EcPoint CreateDummyPoint(const std::shared_ptr<yacl::crypto::EcGroup>& curve) {
  yacl::math::MPInt r;
  r.RandomLtN(curve->GetOrder(), &r);
  return curve->MulBase(r);
}

// Helper to create a dummy MPInt scalar
yacl::math::MPInt CreateDummyScalar(const std::shared_ptr<yacl::crypto::EcGroup>& curve) {
  yacl::math::MPInt r;
  r.RandomLtN(curve->GetOrder(), &r);
  return r;
}

}  // namespace examples::zkp