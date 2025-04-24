#pragma once

#include <vector>
#include <memory> // For std::shared_ptr
#include "yacl/math/mpint/mp_int.h"
#include "yacl/crypto/ecc/ecc_spi.h" // For EcGroup

// Forward declarations if needed, or include full headers
// #include "yacl/crypto/ecc/ec_point.h"

namespace examples::zkp {

// Use YACL's MPInt for scalars
using yacl::math::MPInt;
using yacl::crypto::EcGroup;

// Represents a degree-1 vector polynomial a + b * x.
struct VecPoly1 {
  std::vector<MPInt> a;
  std::vector<MPInt> b;

  VecPoly1() = default;
  VecPoly1(std::vector<MPInt> a_vec, std::vector<MPInt> b_vec);
  ~VecPoly1(); // For clearing memory

  // Creates a zero polynomial of size n.
  static VecPoly1 Zero(size_t n);

  // Evaluates the polynomial at point x.
  std::vector<MPInt> Eval(const MPInt& x) const;

  // Computes the inner product with another VecPoly1, resulting in Poly2.
  // Requires curve order for modular arithmetic.
  struct Poly2 InnerProduct(const VecPoly1& rhs, const MPInt& order) const;
};

// Represents a degree-2 scalar polynomial a + b*x + c*x^2.
struct Poly2 {
  MPInt a;
  MPInt b;
  MPInt c;

  Poly2() = default;
  Poly2(MPInt a_val, MPInt b_val, MPInt c_val);
  ~Poly2(); // For clearing memory

  // Evaluates the polynomial at point x.
  // Requires curve order for modular arithmetic.
  MPInt Eval(const MPInt& x, const MPInt& order) const;
};

#ifdef YACL_ENABLE_YOLOPROOFS
// Represents a degree-3 vector polynomial a + b*x + c*x^2 + d*x^3.
struct VecPoly3 {
  std::vector<MPInt> a;
  std::vector<MPInt> b;
  std::vector<MPInt> c;
  std::vector<MPInt> d;

  VecPoly3() = default;
  VecPoly3(std::vector<MPInt> a_vec, std::vector<MPInt> b_vec,
           std::vector<MPInt> c_vec, std::vector<MPInt> d_vec);
  ~VecPoly3(); // For clearing memory

  // Creates a zero polynomial of size n.
  static VecPoly3 Zero(size_t n);

  // Evaluates the polynomial at point x.
  std::vector<MPInt> Eval(const MPInt& x, const MPInt& order) const;

  // Computes the special inner product with another VecPoly3.
  // Assumes lhs.a and rhs.c are zero. Requires curve order.
  struct Poly6 SpecialInnerProduct(const VecPoly3& rhs, const MPInt& order) const;
};

// Represents coefficients t1..t6 for t1*x + t2*x^2 + ... + t6*x^6.
struct Poly6 {
  MPInt t1, t2, t3, t4, t5, t6;

  Poly6() = default;
  Poly6(MPInt t1_val, MPInt t2_val, MPInt t3_val, MPInt t4_val, MPInt t5_val, MPInt t6_val);
  ~Poly6(); // For clearing memory

  // Evaluates the polynomial at point x. Requires curve order.
  MPInt Eval(const MPInt& x, const MPInt& order) const;
};
#endif // YACL_ENABLE_YOLOPROOFS

// --- Standalone Utility Functions ---

// Computes the inner product of two vectors modulo order.
MPInt InnerProduct(const absl::Span<const MPInt>& a,
                   const absl::Span<const MPInt>& b,
                   const MPInt& order);

// Adds two vectors element-wise modulo order.
std::vector<MPInt> AddVectors(const absl::Span<const MPInt>& a,
                              const absl::Span<const MPInt>& b,
                              const MPInt& order);

// Computes powers of x: [1, x, x^2, ..., x^(n-1)] modulo order.
std::vector<MPInt> Powers(const MPInt& x, size_t n, const MPInt& order);

// Computes sum of powers: 1 + x + ... + x^(n-1) modulo order.
MPInt SumOfPowers(const MPInt& x, size_t n, const MPInt& order);

// Computes x^n (non-modular).
// CAUTION: Use PowMod for cryptographic exponentiation.
MPInt ScalarExpVartime(const MPInt& x, uint64_t n);

} // namespace examples::zkp 