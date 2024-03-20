// Copyright 2024 Ant Group Co., Ltd
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

#include "yacl/crypto/vss/poly.h"

namespace yacl::crypto {

void Polynomial::RandomPolynomial(size_t threshold) {
  MPInt zero_value;
  MPInt::RandomLtN(this->modulus_, &zero_value);
  CreatePolynomial(zero_value, threshold);
}

// Generate a random polynomial with the given zero value, threshold, and
// modulus_.
void Polynomial::CreatePolynomial(const MPInt& zero_value, size_t threshold) {
  // Create a vector to hold the polynomial coefficients.
  std::vector<MPInt> coefficients(threshold);

  // Set the constant term (coefficient[0]) of the polynomial to the given
  // zero_value.
  coefficients[0] = zero_value;

  // Generate random coefficients for the remaining terms of the polynomial.
  for (size_t i = 1; i < threshold; ++i) {
    // Create a variable to hold the current coefficient being generated.
    MPInt coefficient_i;

    // Generate a random integer less than modulus_ and assign it to
    // coefficient_i.
    MPInt::RandomLtN(this->modulus_, &coefficient_i);

    // Set the current coefficient to the generated random value.
    coefficients[i] = coefficient_i;
  }

  // Set the generated coefficients as the coefficients of the polynomial.
  SetCoeffs(coefficients);
}

// Horner's method for computing the polynomial value at a given x.
void Polynomial::EvaluatePolynomial(const MPInt& x, MPInt* result) const {
  // Initialize the result to the constant term (coefficient of highest degree)
  // of the polynomial.
  YACL_ENFORCE(!coeffs_.empty(), "coeffs_ is empty!!!");
  auto tmp = coeffs_.back();

  // Evaluate the polynomial using Horner's method.
  // Starting from the second highest degree coefficient to the constant term
  // (coefficient[0]).
  for (int i = coeffs_.size() - 2; i >= 0; --i) {
    // Create a duplicate of the given x to avoid modifying it.
    // MPInt x_dup = x;

    // Multiply the current result with the x value and update the result.
    // result = x_dup.MulMod(result, modulus_);
    tmp = x.MulMod(tmp, modulus_);
    // Add the next coefficient to the result.
    tmp = tmp.AddMod(coeffs_[i], modulus_);
  }

  *result = tmp;
}

// Lagrange Interpolation algorithm for polynomial interpolation.
void Polynomial::LagrangeInterpolation(absl::Span<const MPInt> xs,
                                       absl::Span<const MPInt> ys,
                                       MPInt* result) const {
  *result = LagrangeInterpolation(xs, ys, 0_mp, modulus_);
}

MPInt Polynomial::LagrangeInterpolation(absl::Span<const MPInt> xs,
                                        absl::Span<const MPInt> ys,
                                        const MPInt& target_x,
                                        const MPInt& modulus) {
  YACL_ENFORCE(xs.size() == ys.size());
  // Initialize the accumulator to store the result of the interpolation.
  auto acc = 0_mp;

  // Loop over each element in the input points xs and interpolate the
  // polynomial.
  for (uint64_t i = 0; i < xs.size(); ++i) {
    auto t = Polynomial::LagrangeComputeAtX(xs, i, ys[i], target_x, modulus);
    acc = t.AddMod(acc, modulus);
  }
  return acc;
}

MPInt Polynomial::LagrangeComputeAtX(absl::Span<const MPInt> xs, uint64_t index,
                                     const MPInt& y, const MPInt& target_x,
                                     const MPInt& modulus) {
  YACL_ENFORCE(index < xs.size(), "X index should be < xs.size()");

  auto num = 1_mp;
  auto denum = 1_mp;
  for (uint64_t j = 0; j < xs.size(); ++j) {
    if (j != index) {
      MPInt xj_sub_targetx = xs[j].SubMod(target_x, modulus);

      // Update the numerator by multiplying it with the current xj.
      num = num.MulMod(xj_sub_targetx, modulus);

      // Compute the difference between the current xj and the current xi
      // (xs[i]).
      MPInt xj_sub_xi = xs[j].SubMod(xs[index], modulus);

      // Update the denominator by multiplying it with the difference.
      denum = denum.MulMod(xj_sub_xi, modulus);
    }
  }
  // Compute the inverse of the denominator modulo the modulus_.
  MPInt denum_inv = denum.InvertMod(modulus);

  return y.MulMod(num, modulus).MulMod(denum_inv, modulus);
}

}  // namespace yacl::crypto
