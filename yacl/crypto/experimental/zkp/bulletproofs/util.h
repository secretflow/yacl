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

#pragma once

#include <cstdint>
#include <vector>

#include "absl/types/span.h"

#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/math/mpint/mp_int.h"
#ifdef _MSC_VER
#include <intrin.h>
#endif

namespace examples::zkp {

// Forward declaration
class VecPoly1;

/**
 * @brief Represents a degree-2 polynomial t_0 + t_1*X + t_2*X^2.
 * Coefficients are assumed to be scalars in the field defined by the curve.
 */
class Poly2 {
 public:
  yacl::math::MPInt t0;
  yacl::math::MPInt t1;
  yacl::math::MPInt t2;

  // Constructor
  Poly2(yacl::math::MPInt t0_val, yacl::math::MPInt t1_val,
        yacl::math::MPInt t2_val);

  // Default constructor (initializes to zero)
  Poly2();

  /**
   * @brief Evaluate the polynomial at a given scalar point x.
   * Performs calculations modulo the curve order.
   *
   * @param x The evaluation point (scalar).
   * @param curve The elliptic curve group providing the field order.
   * @return yacl::math::MPInt The result t(x) mod order.
   */
  yacl::math::MPInt Eval(
      const yacl::math::MPInt& x,
      const std::shared_ptr<yacl::crypto::EcGroup>& curve) const;
};

/**
 * @brief Represents a vector of degree-1 polynomials, where the i-th entry is
 * vec0[i] + vec1[i]*X. Coefficients are assumed to be scalars in the field.
 */
class VecPoly1 {
 public:
  std::vector<yacl::math::MPInt> vec0;  // Constant terms
  std::vector<yacl::math::MPInt> vec1;  // Linear terms

  // Constructor
  VecPoly1(std::vector<yacl::math::MPInt> v0,
           std::vector<yacl::math::MPInt> v1);

  // Default constructor
  VecPoly1() = default;

  /**
   * @brief Creates a VecPoly1 of size n with all coefficients set to zero.
   *
   * @param n The size of the vectors.
   * @return VecPoly1 Zero polynomial vector.
   */
  static VecPoly1 Zero(size_t n);

  /**
   * @brief Computes the inner product of two VecPoly1 vectors, resulting in a
   * Poly2. Uses the Karatsuba-style trick: t1 = <l0+l1, r0+r1> - t0 - t2.
   * Performs calculations modulo the curve order.
   *
   * @param rhs The right-hand side VecPoly1.
   * @param curve The elliptic curve group providing the field order.
   * @return Poly2 The resulting degree-2 polynomial.
   */
  Poly2 InnerProduct(const VecPoly1& rhs,
                     const std::shared_ptr<yacl::crypto::EcGroup>& curve) const;

  /**
   * @brief Evaluates each polynomial in the vector at the given scalar point x.
   * Performs calculations modulo the curve order.
   *
   * @param x The evaluation point (scalar).
   * @param curve The elliptic curve group providing the field order.
   * @return std::vector<yacl::math::MPInt> Vector of evaluated results.
   */
  std::vector<yacl::math::MPInt> Eval(
      const yacl::math::MPInt& x,
      const std::shared_ptr<yacl::crypto::EcGroup>& curve) const;

  /**
   * @brief Destructor to clear sensitive scalar data.
   */
  ~VecPoly1();

  // Delete copy operations to prevent accidental copying of potentially large
  // vectors
  VecPoly1(const VecPoly1&) = delete;
  VecPoly1& operator=(const VecPoly1&) = delete;

  // Allow move operations
  VecPoly1(VecPoly1&&) = default;
  VecPoly1& operator=(VecPoly1&&) = default;
};

//----------------------------------------
// Standalone Utility Functions
//----------------------------------------

/**
 * @brief Calculate inner product of two scalar vectors modulo the curve order.
 * result = sum(a[i] * b[i]) mod order
 *
 * @param a First vector.
 * @param b Second vector.
 * @param curve The elliptic curve group providing the field order.
 * @return yacl::math::MPInt Inner product result modulo order.
 * @throws yacl::Exception if vectors have different sizes.
 */
yacl::math::MPInt InnerProduct(
    // const std::vector<yacl::math::MPInt>& a,
    // const std::vector<yacl::math::MPInt>& b,
    absl::Span<const yacl::math::MPInt> a,
    absl::Span<const yacl::math::MPInt> b,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve);

/**
 * @brief Adds two scalar vectors element-wise modulo the curve order.
 * out[i] = (a[i] + b[i]) mod order
 *
 * @param a First vector.
 * @param b Second vector.
 * @param curve The elliptic curve group providing the field order.
 * @return std::vector<yacl::math::MPInt> Resultant vector.
 * @throws yacl::Exception if vectors have different sizes.
 */
std::vector<yacl::math::MPInt> AddVec(
    const std::vector<yacl::math::MPInt>& a,
    const std::vector<yacl::math::MPInt>& b,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve);

/**
 * @brief Create a vector containing powers of a scalar: [base^0, base^1, ...,
 * base^(n-1)] mod order.
 *
 * @param base Base scalar.
 * @param n Number of powers to generate.
 * @param curve The elliptic curve group providing the field order.
 * @return std::vector<yacl::math::MPInt> Vector of powers modulo order.
 */
std::vector<yacl::math::MPInt> ExpIterVector(
    const yacl::math::MPInt& base, size_t n,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve);

/**
 * @brief Calculate the sum of powers: base^0 + base^1 + ... + base^(n-1) mod
 * order.
 *
 * @param base Base scalar.
 * @param n Number of terms.
 * @param curve The elliptic curve group providing the field order.
 * @return yacl::math::MPInt Sum of powers modulo order.
 */
yacl::math::MPInt SumOfPowers(
    const yacl::math::MPInt& base, size_t n,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve);

/**
 * @brief Calculate scalar exponentiation: base^exp mod order.
 *
 * @param base Base scalar.
 * @param exp Exponent.
 * @param curve The elliptic curve group providing the field order.
 * @return yacl::math::MPInt Result modulo order.
 */
yacl::math::MPInt ScalarExp(
    const yacl::math::MPInt& base, size_t exp,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve);

/**
 * @brief Utility function to compute floor(log2(x)).
 */
inline size_t FloorLog2(size_t n) {
  if (n == 0) {
    // Returning -1 for size_t is problematic. Throwing is safer.
    YACL_THROW("FloorLog2 of 0 is undefined.");
  }
#if defined(__GNUC__) || defined(__clang__)
  // __builtin_clzll expects unsigned long long. size_t might be smaller/larger.
  // Let's be safe with casting.
  return (sizeof(unsigned long long) * 8 - 1) -
         __builtin_clzll(static_cast<unsigned long long>(n));
#elif defined(_MSC_VER)
  unsigned long index;
  // _BitScanReverse64 expects __int64.
  if (_BitScanReverse64(&index, static_cast<unsigned __int64>(n))) {
    return index;
  }
  YACL_THROW("FloorLog2 failed for a non-zero number, this should not happen.");
#else
  // Portable but slower fallback
  size_t log = 0;
  while ((static_cast<size_t>(1) << (log + 1)) <= n &&
         (log + 1) < sizeof(size_t) * 8) {
    log++;
  }
  return log;
#endif
}

yacl::crypto::EcPoint MultiScalarMul(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    const std::vector<yacl::math::MPInt>& scalars,
    const std::vector<yacl::crypto::EcPoint>& points);

// Helper to create a random MPInt scalar
yacl::math::MPInt CreateRandomScalar(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve);

size_t NextPowerOfTwo(size_t n);

// Represents a vector of polynomials of degree 3
struct VecPoly3 {
  std::vector<yacl::math::MPInt> T0, T1, T2, T3;
  VecPoly3(size_t n) : T0(n), T1(n), T2(n), T3(n) {}

  // Evaluate all polynomials at x
  std::vector<yacl::math::MPInt> Eval(
      const yacl::math::MPInt& x,
      const std::shared_ptr<yacl::crypto::EcGroup>& curve) const;
};

// Represents a polynomial of degree 6
struct Poly6 {
  yacl::math::MPInt T0, T1, T2, T3, T4, T5, T6;
  Poly6() : T0(0), T1(0), T2(0), T3(0), T4(0), T5(0), T6(0) {}

  yacl::math::MPInt Eval(
      const yacl::math::MPInt& x,
      const std::shared_ptr<yacl::crypto::EcGroup>& curve) const;
};

// Special inner product for R1CS polynomials
Poly6 SpecialInnerProduct(const VecPoly3& l, const VecPoly3& r,
                          const std::shared_ptr<yacl::crypto::EcGroup>& curve);

}  // namespace examples::zkp