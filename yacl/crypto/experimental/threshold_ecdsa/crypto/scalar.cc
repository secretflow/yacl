#include "yacl/crypto/experimental/threshold_ecdsa/crypto/scalar.h"
#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"

#include <algorithm>
#include <stdexcept>

#include "yacl/crypto/experimental/threshold_ecdsa/crypto/bigint_utils.h"

namespace tecdsa {
namespace {

const Scalar::BigInt kSecp256k1OrderMpInt(
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
const mpz_class kSecp256k1Order(
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

Scalar::BigInt MpzToMpInt(const mpz_class& value) {
  return Scalar::BigInt(value.get_str(10), 10);
}

mpz_class MpIntToMpz(const Scalar::BigInt& value) {
  mpz_class out;
  const std::string decimal = value.ToString();
  if (mpz_set_str(out.get_mpz_t(), decimal.c_str(), 10) != 0) {
    TECDSA_THROW("failed to convert MPInt to mpz_class");
  }
  return out;
}

Scalar::BigInt NormalizeToQ(const Scalar::BigInt& input) {
  return bigint::NormalizeMod(input, kSecp256k1OrderMpInt);
}

Scalar::BigInt ImportBigEndian(std::span<const uint8_t> bytes) {
  if (bytes.empty()) {
    TECDSA_THROW_ARGUMENT("Big-endian input must not be empty");
  }
  return bigint::FromBigEndian(bytes);
}

}  // namespace

Scalar::Scalar() : Scalar(BigInt(0)) {}

Scalar::Scalar(const BigInt& value) : value_(NormalizeToQ(value)), value_mpz_(MpIntToMpz(value_)) {}

Scalar::Scalar(const mpz_class& value) : Scalar(MpzToMpInt(value)) {}

Scalar Scalar::FromUint64(uint64_t value) {
  return Scalar(BigInt(value));
}

Scalar Scalar::FromBigEndianModQ(std::span<const uint8_t> bytes) {
  return Scalar(ImportBigEndian(bytes));
}

Scalar Scalar::FromCanonicalBytes(std::span<const uint8_t> bytes) {
  if (bytes.size() != 32) {
    TECDSA_THROW_ARGUMENT("Canonical scalar must be exactly 32 bytes");
  }

  BigInt imported = ImportBigEndian(bytes);
  if (imported >= kSecp256k1OrderMpInt) {
    TECDSA_THROW_ARGUMENT("Canonical scalar is out of range");
  }
  return Scalar(imported);
}

std::array<uint8_t, 32> Scalar::ToCanonicalBytes() const {
  std::array<uint8_t, 32> out{};
  const Bytes fixed = bigint::ToFixedWidth(value_, out.size());
  std::copy(fixed.begin(), fixed.end(), out.begin());
  return out;
}

const Scalar::BigInt& Scalar::mp_value() const {
  return value_;
}

const mpz_class& Scalar::value() const {
  return value_mpz_;
}

Scalar Scalar::operator+(const Scalar& other) const {
  return Scalar(value_ + other.value_);
}

Scalar Scalar::operator-(const Scalar& other) const {
  return Scalar(value_ - other.value_);
}

Scalar Scalar::operator*(const Scalar& other) const {
  return Scalar(value_ * other.value_);
}

Scalar Scalar::InverseModQ() const {
  if (value_ == 0) {
    TECDSA_THROW_ARGUMENT("zero has no inverse modulo q");
  }

  const auto inv = bigint::TryInvertMod(value_, kSecp256k1OrderMpInt);
  if (!inv.has_value()) {
    TECDSA_THROW_ARGUMENT("failed to invert scalar modulo q");
  }
  return Scalar(*inv);
}

bool Scalar::operator==(const Scalar& other) const {
  return value_ == other.value_;
}

bool Scalar::operator!=(const Scalar& other) const {
  return !(*this == other);
}

const Scalar::BigInt& Scalar::ModulusQMpInt() {
  return kSecp256k1OrderMpInt;
}

const mpz_class& Scalar::ModulusQ() {
  return kSecp256k1Order;
}

}  // namespace tecdsa
