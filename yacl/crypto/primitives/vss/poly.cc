#include "yacl/crypto/primitives/vss/poly.h"

namespace yacl::crypto {

// Generate a random polynomial with the given zero value, threshold, and
// modulus.
void Polynomial::CreatePolynomial(const math::MPInt& zero_value,
                                  const size_t threshold,
                                  const math::MPInt& modulus) {
  // Create a vector to hold the polynomial coefficients.
  std::vector<math::MPInt> coefficients(threshold);

  // Set the constant term (coefficient[0]) of the polynomial to the given
  // zero_value.
  coefficients[0] = zero_value;

  // Generate random coefficients for the remaining terms of the polynomial.
  for (size_t i = 1; i < threshold; ++i) {
    // Create a variable to hold the current coefficient being generated.
    math::MPInt coefficient_i;

    // Generate a random integer less than modulus and assign it to
    // coefficient_i.
    math::MPInt::RandomLtN(modulus, &coefficient_i);

    // Set the current coefficient to the generated random value.
    coefficients[i] = coefficient_i;
  }

  // Set the generated coefficients as the coefficients of the polynomial.
  SetCoeffs(coefficients);
}

// Horner's method for computing the polynomial value at a given x.
void Polynomial::EvaluatePolynomial(const math::MPInt& x,
                                    const math::MPInt& modulus,
                                    math::MPInt& result) {
  // Initialize the result to the constant term (coefficient of highest degree)
  // of the polynomial.
  if (!coeffs_.empty()) {
    result = coeffs_.back();
  } else {
    // If the coefficients vector is empty, print a warning message.
    std::cout << "coeffs_ is empty!!!" << std::endl;
  }

  // Evaluate the polynomial using Horner's method.
  // Starting from the second highest degree coefficient to the constant term
  // (coefficient[0]).
  for (int i = coeffs_.size() - 2; i >= 0; --i) {
    // Create a duplicate of the given x to avoid modifying it.
    math::MPInt x_dup = x;

    // Multiply the current result with the x value and update the result.
    result = x_dup.MulMod(result, modulus);

    // Add the next coefficient to the result.
    result = result.AddMod(coeffs_[i], modulus);
  }
}

// Lagrange Interpolation algorithm for polynomial interpolation.
void Polynomial::LagrangeInterpolation(std::vector<math::MPInt>& xs,
                                       std::vector<math::MPInt>& ys,
                                       math::MPInt& prime,
                                       math::MPInt& result) {
  // Initialize the accumulator to store the result of the interpolation.
  math::MPInt acc(0);

  // Loop over each element in the input points xs and interpolate the
  // polynomial.
  for (size_t i = 0; i < xs.size(); ++i) {
    // Initialize the numerator and denominator for Lagrange interpolation.
    math::MPInt num(1);
    math::MPInt denum(1);

    // Compute the numerator and denominator for the current interpolation
    // point.
    for (size_t j = 0; j < xs.size(); ++j) {
      if (j != i) {
        math::MPInt xj = xs[j];

        // Duplicate the numerator to calculate the current term without the
        // current xj.
        math::MPInt num_dup = num;
        // Update the numerator by multiplying it with the current xj.
        num = num.MulMod(xj, prime);

        // Compute the difference between the current xj and the current xi
        // (xs[i]).
        math::MPInt xj_sub_xi = xj.SubMod(xs[i], prime);

        // Update the denominator by multiplying it with the difference.
        denum = denum.MulMod(xj_sub_xi, prime);
      }
    }

    // Compute the inverse of the denominator modulo the prime.
    math::MPInt denum_inv = denum.InvertMod(prime);

    // Compute the current interpolated value and add it to the accumulator.
    acc = ys[i].MulMod(num, prime).MulMod(denum_inv, prime).AddMod(acc, prime);
  }

  // Store the final interpolated result in the 'result' variable.
  result = acc;
}
}  // namespace yacl::crypto
