#include "yacl/crypto/experimental/threshold_ecdsa/crypto/scalar.h"
#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"

#include <algorithm>
#include <stdexcept>

namespace tecdsa {
namespace {

const mpz_class kSecp256k1Order(
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

mpz_class NormalizeToQ(const mpz_class& input) {
  mpz_class normalized = input % kSecp256k1Order;
  if (normalized < 0) {
    normalized += kSecp256k1Order;
  }
  return normalized;
}

mpz_class ImportBigEndian(std::span<const uint8_t> bytes) {
  if (bytes.empty()) {
    TECDSA_THROW_ARGUMENT("Big-endian input must not be empty");
  }

  mpz_class out;
  mpz_import(out.get_mpz_t(), bytes.size(), 1, sizeof(uint8_t), 1, 0, bytes.data());
  return out;
}

}  // namespace

Scalar::Scalar() : value_(0) {}

Scalar::Scalar(const mpz_class& value) : value_(NormalizeToQ(value)) {}

Scalar Scalar::FromUint64(uint64_t value) {
  return Scalar(mpz_class(value));
}

Scalar Scalar::FromBigEndianModQ(std::span<const uint8_t> bytes) {
  return Scalar(ImportBigEndian(bytes));
}

Scalar Scalar::FromCanonicalBytes(std::span<const uint8_t> bytes) {
  if (bytes.size() != 32) {
    TECDSA_THROW_ARGUMENT("Canonical scalar must be exactly 32 bytes");
  }

  mpz_class imported = ImportBigEndian(bytes);
  if (imported >= kSecp256k1Order) {
    TECDSA_THROW_ARGUMENT("Canonical scalar is out of range");
  }
  return Scalar(imported);
}

std::array<uint8_t, 32> Scalar::ToCanonicalBytes() const {
  std::array<uint8_t, 32> out{};

  if (value_ == 0) {
    return out;
  }

  size_t count = 0;
  mpz_export(out.data(), &count, 1, sizeof(uint8_t), 1, 0, value_.get_mpz_t());
  if (count > out.size()) {
    TECDSA_THROW("Scalar is larger than 32 bytes");
  }

  const size_t offset = out.size() - count;
  std::rotate(out.begin(), out.begin() + count, out.end());
  std::fill(out.begin(), out.begin() + offset, 0);
  return out;
}

const mpz_class& Scalar::value() const {
  return value_;
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

  mpz_class inv;
  if (mpz_invert(inv.get_mpz_t(), value_.get_mpz_t(), kSecp256k1Order.get_mpz_t()) == 0) {
    TECDSA_THROW_ARGUMENT("failed to invert scalar modulo q");
  }
  return Scalar(inv);
}

bool Scalar::operator==(const Scalar& other) const {
  return value_ == other.value_;
}

bool Scalar::operator!=(const Scalar& other) const {
  return !(*this == other);
}

const mpz_class& Scalar::ModulusQ() {
  return kSecp256k1Order;
}

}  // namespace tecdsa
