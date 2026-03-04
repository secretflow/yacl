#include "yacl/crypto/experimental/threshold_ecdsa/crypto/ecdsa_verify.h"
#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"

#include <optional>
#include <span>
#include <stdexcept>

namespace tecdsa {
namespace {

Scalar XCoordinateModQ(const ECPoint& point) {
  const Bytes compressed = point.ToCompressedBytes();
  if (compressed.size() != 33) {
    TECDSA_THROW_ARGUMENT("invalid compressed point length");
  }
  const std::span<const uint8_t> x_bytes(compressed.data() + 1, 32);
  return Scalar::FromBigEndianModQ(x_bytes);
}

}  // namespace

bool VerifyEcdsaSignatureMath(const ECPoint& public_key,
                              std::span<const uint8_t> msg32,
                              const Scalar& r,
                              const Scalar& s) {
  // Align with GG2019's final signature check: standard ECDSA verification on
  // secp256k1.
  if (msg32.size() != 32 || r.value() == 0 || s.value() == 0) {
    return false;
  }

  try {
    const Scalar z = Scalar::FromBigEndianModQ(msg32);
    const Scalar w = s.InverseModQ();
    const Scalar u1 = z * w;
    const Scalar u2 = r * w;

    std::optional<ECPoint> left;
    std::optional<ECPoint> right;
    if (u1.value() != 0) {
      left = ECPoint::GeneratorMultiply(u1);
    }
    if (u2.value() != 0) {
      right = public_key.Mul(u2);
    }

    ECPoint reconstructed;
    if (left.has_value() && right.has_value()) {
      reconstructed = left->Add(*right);
    } else if (left.has_value()) {
      reconstructed = *left;
    } else if (right.has_value()) {
      reconstructed = *right;
    } else {
      return false;
    }

    const Scalar v = XCoordinateModQ(reconstructed);
    return v == r;
  } catch (const std::exception&) {
    return false;
  }
}

}  // namespace tecdsa
