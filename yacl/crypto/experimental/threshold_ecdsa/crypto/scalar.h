#pragma once

#include <array>
#include <cstdint>
#include <span>

#include "yacl/math/mpint/mp_int.h"

namespace tecdsa {

class Scalar {
 public:
  using BigInt = yacl::math::MPInt;

  Scalar();
  explicit Scalar(const BigInt& value);

  static Scalar FromUint64(uint64_t value);
  static Scalar FromBigEndianModQ(std::span<const uint8_t> bytes);
  static Scalar FromCanonicalBytes(std::span<const uint8_t> bytes);

  std::array<uint8_t, 32> ToCanonicalBytes() const;

  const BigInt& mp_value() const;
  const BigInt& value() const;

  Scalar operator+(const Scalar& other) const;
  Scalar operator-(const Scalar& other) const;
  Scalar operator*(const Scalar& other) const;
  Scalar InverseModQ() const;

  bool operator==(const Scalar& other) const;
  bool operator!=(const Scalar& other) const;

  static const BigInt& ModulusQMpInt();
  static const BigInt& ModulusQ();

 private:
  BigInt value_;
};

}  // namespace tecdsa
