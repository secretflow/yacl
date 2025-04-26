#include "zkp/bulletproofs/util.h"

#include <algorithm>
#include <cstring>

namespace examples::zkp {

// Implementation of VecPoly1 methods

VecPoly1 VecPoly1::Zero(size_t n) {
  std::vector<yacl::math::MPInt> vec0(n, yacl::math::MPInt(0));
  std::vector<yacl::math::MPInt> vec1(n, yacl::math::MPInt(0));
  return VecPoly1(std::move(vec0), std::move(vec1));
}

Poly2 VecPoly1::InnerProduct(const VecPoly1& rhs) const {
  // Uses Karatsuba's method
  const VecPoly1& l = *this;
  const VecPoly1& r = rhs;

  yacl::math::MPInt t0 = ::examples::zkp::InnerProduct(l.vec0, r.vec0);
  yacl::math::MPInt t2 = ::examples::zkp::InnerProduct(l.vec1, r.vec1);

  std::vector<yacl::math::MPInt> l0_plus_l1 = AddVec(l.vec0, l.vec1);
  std::vector<yacl::math::MPInt> r0_plus_r1 = AddVec(r.vec0, r.vec1);

  yacl::math::MPInt t1 = ::examples::zkp::InnerProduct(l0_plus_l1, r0_plus_r1) - t0 - t2;

  return Poly2(t0, t1, t2);
}

std::vector<yacl::math::MPInt> VecPoly1::Eval(const yacl::math::MPInt& x) const {
  size_t n = vec0.size();
  std::vector<yacl::math::MPInt> out(n, yacl::math::MPInt(0));
  
  for (size_t i = 0; i < n; i++) {
    out[i] = vec0[i] + vec1[i] * x;
  }
  
  return out;
}

VecPoly1::~VecPoly1() {
  // Clear sensitive data
  for (auto& e : vec0) {
    e = yacl::math::MPInt(0);
  }
  for (auto& e : vec1) {
    e = yacl::math::MPInt(0);
  }
}

// Implementation of Poly2 methods

yacl::math::MPInt Poly2::Eval(const yacl::math::MPInt& x) const {
  return t0 + x * (t1 + x * t2);
}

Poly2::~Poly2() {
  // Clear sensitive data
  t0 = yacl::math::MPInt(0);
  t1 = yacl::math::MPInt(0);
  t2 = yacl::math::MPInt(0);
}

// Implementation of utility functions

yacl::math::MPInt InnerProduct(const std::vector<yacl::math::MPInt>& a,
                             const std::vector<yacl::math::MPInt>& b) {
  if (a.size() != b.size()) {
    throw yacl::Exception("Vector sizes don't match for inner product");
  }
  
  yacl::math::MPInt result(0);
  for (size_t i = 0; i < a.size(); i++) {
    result = result + a[i] * b[i];
  }
  
  return result;
}

std::vector<yacl::math::MPInt> AddVec(const std::vector<yacl::math::MPInt>& a,
                                    const std::vector<yacl::math::MPInt>& b) {
  if (a.size() != b.size()) {
    throw yacl::Exception("Vector sizes don't match for vector addition");
  }
  
  std::vector<yacl::math::MPInt> out(a.size(), yacl::math::MPInt(0));
  for (size_t i = 0; i < a.size(); i++) {
    out[i] = a[i] + b[i];
  }
  
  return out;
}

std::vector<yacl::math::MPInt> ExpIterVector(const yacl::math::MPInt& x, size_t n) {
  std::vector<yacl::math::MPInt> result;
  result.reserve(n);
  
  yacl::math::MPInt current(1);
  for (size_t i = 0; i < n; i++) {
    result.push_back(current);
    current = current * x;
  }
  
  return result;
}

yacl::math::MPInt ScalarExpVartime(const yacl::math::MPInt& x, uint64_t n) {
  yacl::math::MPInt result(1);
  yacl::math::MPInt aux = x;
  
  while (n > 0) {
    uint64_t bit = n & 1;
    if (bit == 1) {
      result = result * aux;
    }
    n = n >> 1;
    if (n > 0) {  // Skip the last multiply
      aux = aux * aux;
    }
  }
  
  return result;
}

yacl::math::MPInt SumOfPowers(const yacl::math::MPInt& x, size_t n) {
  // Check if n is a power of 2
  if (n == 0) {
    return yacl::math::MPInt(0);
  }
  
  if (n == 1) {
    return yacl::math::MPInt(1);
  }
  
  // Check if n is a power of 2
  if ((n & (n - 1)) != 0) {
    // n is not a power of 2, use slow method
    return SumOfPowersSlow(x, n);
  }
  
  // Fast method for powers of 2
  yacl::math::MPInt result = yacl::math::MPInt(1) + x;
  yacl::math::MPInt factor = x;
  size_t m = n;
  
  while (m > 2) {
    factor = factor * factor;
    result = result + factor * result;
    m = m / 2;
  }
  
  return result;
}

yacl::math::MPInt SumOfPowersSlow(const yacl::math::MPInt& x, size_t n) {
  yacl::math::MPInt result(0);
  yacl::math::MPInt current(1);
  
  for (size_t i = 0; i < n; i++) {
    result = result + current;
    current = current * x;
  }
  
  return result;
}

std::array<uint8_t, 32> Read32(const std::vector<uint8_t>& data) {
  if (data.size() < 32) {
    throw yacl::Exception("Input data must be at least 32 bytes");
  }
  
  std::array<uint8_t, 32> result;
  std::copy_n(data.begin(), 32, result.begin());
  
  return result;
}

} // namespace examples::zkp