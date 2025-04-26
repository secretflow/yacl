#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include "yacl/base/exception.h"
#include "yacl/math/mpint/mp_int.h"

namespace examples::zkp {

// Forward declaration for inner product function
yacl::math::MPInt InnerProduct(const std::vector<yacl::math::MPInt>& a,
                             const std::vector<yacl::math::MPInt>& b);

/**
 * @brief Represents a degree-1 vector polynomial a + b·x
 */
class VecPoly1 {
 public:
  std::vector<yacl::math::MPInt> vec0;  // Coefficient of x^0 (constant term)
  std::vector<yacl::math::MPInt> vec1;  // Coefficient of x^1

  /**
   * @brief Constructs a new VecPoly1 object
   */
  VecPoly1(std::vector<yacl::math::MPInt> vec0, std::vector<yacl::math::MPInt> vec1)
      : vec0(std::move(vec0)), vec1(std::move(vec1)) {}

  /**
   * @brief Create a zero polynomial of length n
   */
  static VecPoly1 Zero(size_t n);

  /**
   * @brief Compute inner product with another vector polynomial
   * Uses Karatsuba's method
   */
  class Poly2 InnerProduct(const VecPoly1& rhs) const;

  /**
   * @brief Evaluate the polynomial at point x
   */
  std::vector<yacl::math::MPInt> Eval(const yacl::math::MPInt& x) const;

  /**
   * @brief Destructor to clear sensitive data
   */
  ~VecPoly1();
};

/**
 * @brief Represents a degree-2 scalar polynomial a + b·x + c·x^2
 */
class Poly2 {
 public:
  yacl::math::MPInt t0;  // Coefficient of x^0 (constant term)
  yacl::math::MPInt t1;  // Coefficient of x^1
  yacl::math::MPInt t2;  // Coefficient of x^2

  /**
   * @brief Constructs a new Poly2 object
   */
  Poly2(const yacl::math::MPInt& t0, const yacl::math::MPInt& t1, const yacl::math::MPInt& t2)
      : t0(t0), t1(t1), t2(t2) {}

  /**
   * @brief Evaluate the polynomial at point x
   */
  yacl::math::MPInt Eval(const yacl::math::MPInt& x) const;

  /**
   * @brief Destructor to clear sensitive data
   */
  ~Poly2();
};

/**
 * @brief Add two vectors of MPInt
 */
std::vector<yacl::math::MPInt> AddVec(const std::vector<yacl::math::MPInt>& a,
                                    const std::vector<yacl::math::MPInt>& b);

/**
 * @brief Creates an iterator of powers of x
 * Returns vector of [1, x, x^2, ..., x^(n-1)]
 */
std::vector<yacl::math::MPInt> ExpIterVector(const yacl::math::MPInt& x, size_t n);

/**
 * @brief Raises x to the power n using binary exponentiation
 */
yacl::math::MPInt ScalarExpVartime(const yacl::math::MPInt& x, uint64_t n);

/**
 * @brief Takes the sum of all powers of x, up to n
 * If n is a power of 2, uses efficient algorithm with 2*log(n) multiplications
 */
yacl::math::MPInt SumOfPowers(const yacl::math::MPInt& x, size_t n);

/**
 * @brief Takes the sum of all powers of x, up to n (slow version)
 */
yacl::math::MPInt SumOfPowersSlow(const yacl::math::MPInt& x, size_t n);

/**
 * @brief Given data with len >= 32, return the first 32 bytes
 */
std::array<uint8_t, 32> Read32(const std::vector<uint8_t>& data);

} // namespace examples::zkp