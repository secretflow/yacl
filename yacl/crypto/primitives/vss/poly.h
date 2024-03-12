/*
 * Copyright 2024 Ant Group Co., Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include "yacl/math/mpint/mp_int.h"

namespace yacl::crypto {

using math::MPInt;

// Polynomial class for polynomial manipulation and sharing.
class Polynomial {
 public:
  /**
   * @brief Construct a new Polynomial object with modulus
   *
   * @param modulus
   */
  Polynomial(const MPInt& modulus) : modulus_(modulus) {}

  /**
   * @brief Destroy the Polynomial object
   *
   */
  ~Polynomial(){};

  /**
   * @brief Creates a random polynomial with the given zero_value, threshold,
   * and modulus.
   *
   * @param zero_value Set poly(0) to be the zero_value(secret value).
   * @param threshold
   * @param modulus
   */
  void CreatePolynomial(const MPInt& zero_value, size_t threshold);
  void RandomPolynomial(size_t threshold);

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
  void EvaluatePolynomial(const MPInt& x, MPInt* result) const;

  /**
   * @brief Performs Lagrange interpolation to interpolate the polynomial based
   * on the given points.
   *
   * @param xs
   * @param ys
   * @param prime
   * @param result
   */
  void LagrangeInterpolation(absl::Span<const MPInt>, absl::Span<const MPInt>,
                             MPInt* result) const;

  /**
   * @brief Sets the coefficients of the polynomial to the provided vector of
   * MPInt.
   *
   * @param coefficients
   */
  void SetCoeffs(const std::vector<MPInt>& coefficients) {
    coeffs_ = coefficients;
  }

  /**
   * @brief Returns the coefficients of the polynomial as a vector of MPInt.
   *
   * @return std::vector<MPInt>
   */
  std::vector<MPInt> GetCoeffs() const { return coeffs_; }

  static MPInt LagrangeInterpolation(absl::Span<const MPInt> xs,
                                     absl::Span<const MPInt> ys,
                                     const MPInt& target_x,
                                     const MPInt& modulus);
  static MPInt LagrangeComputeAtX(absl::Span<const MPInt> xs, uint64_t index,
                                  const MPInt& y, const MPInt& target_x,
                                  const MPInt& modulus);

 private:
  // Vector to store the coefficients of the polynomial.
  std::vector<MPInt> coeffs_;
  MPInt modulus_;
};

}  // namespace yacl::crypto
