#pragma once

#include "yacl/math/mpint/mp_int.h"

namespace yacl::crypto {

// Polynomial class for polynomial manipulation and sharing.
class Polynomial {
 public:
  /**
   * @brief Construct a new Polynomial object
   *
   */
  Polynomial(){};

  /**
   * @brief Construct a new Polynomial object with modulus
   *
   * @param modulus
   */
  Polynomial(math::MPInt modulus) : modulus_(modulus) {}

  /**
   * @brief Destroy the Polynomial object
   *
   */
  ~Polynomial(){};

  /**
   * @brief Creates a random polynomial with the given zero_value, threshold,
   * and modulus.
   *
   * @param zero_value
   * @param threshold
   * @param modulus
   */
  void CreatePolynomial(const math::MPInt& zero_value, const size_t threshold,
                        const math::MPInt& modulus);

  /**
   * @brief Horner's method, also known as Horner's rule or Horner's scheme, is
   * an algorithm for the efficient evaluation of polynomials. It is used to
   * compute the value of a polynomial at a given point without the need for
   * repeated multiplication and addition operations. The method is particularly
   * useful for high-degree polynomials.
   *
   * The general form of a polynomial is:
   *
   * f(x) = a_n * x^n + a_{n-1} * x^{n-1} + ... + a_1 * x + a_0
   *
   * Horner's method allows us to compute the value of the polynomial f(x) at a
   * specific point x_0 in a more efficient way by factoring out the common
   * terms:
   *
   * f(x_0) = (((a_n * x_0 + a_{n-1}) * x_0 + a_{n-2}) * x_0 + ... + a_1) * x_0
   * + a_0
   *
   * The algorithm proceeds iteratively, starting with the coefficient of the
   * highest degree term, and at each step, it multiplies the current partial
   * result by the input point x_0 and adds the next coefficient.
   *
   * The advantages of using Horner's method include reducing the number of
   * multiplications and additions compared to the straightforward
   *
   * @param x
   * @param modulus
   * @param result
   */
  void EvaluatePolynomial(const math::MPInt& x, math::MPInt& result) const;

  /**
   * @brief Performs Lagrange interpolation to interpolate the polynomial based
   * on the given points.
   *
   * @param xs
   * @param ys
   * @param prime
   * @param result
   */
  void LagrangeInterpolation(std::vector<math::MPInt>& xs,
                             std::vector<math::MPInt>& ys,
                             math::MPInt& result) const;

  /**
   * @brief Sets the coefficients of the polynomial to the provided vector of
   * MPInt.
   *
   * @param coefficients
   */
  void SetCoeffs(const std::vector<math::MPInt>& coefficients) {
    coeffs_ = coefficients;
  }

  /**
   * @brief Returns the coefficients of the polynomial as a vector of MPInt.
   *
   * @return std::vector<math::MPInt>
   */
  std::vector<math::MPInt> GetCoeffs() const { return coeffs_; }

 private:
  // Vector to store the coefficients of the polynomial.
  std::vector<math::MPInt> coeffs_;
  math::MPInt modulus_;
};

}  // namespace yacl::crypto
