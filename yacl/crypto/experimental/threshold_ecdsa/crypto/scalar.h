#pragma once

#include <array>
#include <cstdint>
#include <span>

#include <gmpxx.h>

#include "yacl/math/mpint/mp_int.h"

namespace tecdsa {

class Scalar {
 public:
  using BigInt = yacl::math::MPInt;

  Scalar();
  explicit Scalar(const BigInt& value);
  explicit Scalar(const mpz_class& value);

  static Scalar FromUint64(uint64_t value);
  static Scalar FromBigEndianModQ(std::span<const uint8_t> bytes);
  static Scalar FromCanonicalBytes(std::span<const uint8_t> bytes);

  std::array<uint8_t, 32> ToCanonicalBytes() const;

  const BigInt& mp_value() const;
  const mpz_class& value() const;

  Scalar operator+(const Scalar& other) const;
  Scalar operator-(const Scalar& other) const;
  Scalar operator*(const Scalar& other) const;
  Scalar InverseModQ() const;

  bool operator==(const Scalar& other) const;
  bool operator!=(const Scalar& other) const;

  static const BigInt& ModulusQMpInt();
  static const mpz_class& ModulusQ();

 private:
  BigInt value_;
  mpz_class value_mpz_;
};

}  // namespace tecdsa
