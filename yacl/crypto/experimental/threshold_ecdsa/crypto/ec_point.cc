#include "yacl/crypto/experimental/threshold_ecdsa/crypto/ec_point.h"
#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <memory>
#include <stdexcept>

#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/math/mpint/mp_int.h"

namespace tecdsa {
namespace {

using yacl::crypto::EcGroup;
using yacl::crypto::EcPoint;
using yacl::crypto::EcGroupFactory;
using yacl::crypto::PointOctetFormat;
using yacl::math::MPInt;

EcGroup& GetCurve() {
  static std::unique_ptr<EcGroup> curve = []() {
    auto created = EcGroupFactory::Instance().Create("secp256k1", yacl::ArgLib = "openssl");
    if (created == nullptr) {
      TECDSA_THROW("Failed to create secp256k1 curve via yacl openssl backend");
    }
    return created;
  }();
  return *curve;
}

MPInt ScalarToMpInt(const Scalar& scalar) {
  const std::array<uint8_t, 32> scalar_bytes = scalar.ToCanonicalBytes();
  MPInt mp;
  mp.FromMagBytes(scalar_bytes, yacl::Endian::big);
  return mp;
}

EcPoint DeserializeCompressed(const std::array<uint8_t, 33>& compressed) {
  try {
    EcPoint point =
        GetCurve().DeserializePoint(compressed, PointOctetFormat::X962Compressed);
    if (!GetCurve().IsInCurveGroup(point) || GetCurve().IsInfinity(point)) {
      TECDSA_THROW_ARGUMENT("Compressed point is not a valid secp256k1 point");
    }
    return point;
  } catch (const std::exception&) {
    TECDSA_THROW_ARGUMENT("Compressed point is not a valid secp256k1 point");
  }
}

std::array<uint8_t, 33> SerializeCompressed(const EcPoint& point) {
  const auto encoded =
      GetCurve().SerializePoint(point, PointOctetFormat::X962Compressed);

  std::array<uint8_t, 33> out{};
  if (encoded.size() != static_cast<int64_t>(out.size())) {
    TECDSA_THROW("Failed to serialize secp256k1 point");
  }
  std::memcpy(out.data(), encoded.data<uint8_t>(), out.size());
  if (out[0] != 0x02 && out[0] != 0x03) {
    TECDSA_THROW("Failed to serialize secp256k1 point");
  }
  return out;
}

}  // namespace

ECPoint::ECPoint() {
  compressed_.fill(0);
  compressed_[0] = 0x02;
}

ECPoint ECPoint::FromCompressed(std::span<const uint8_t> compressed_bytes) {
  if (compressed_bytes.size() != 33) {
    TECDSA_THROW_ARGUMENT("Compressed point must be 33 bytes");
  }
  if (compressed_bytes[0] != 0x02 && compressed_bytes[0] != 0x03) {
    TECDSA_THROW_ARGUMENT("Compressed point is not a valid secp256k1 point");
  }

  std::array<uint8_t, 33> compressed{};
  std::copy(compressed_bytes.begin(), compressed_bytes.end(), compressed.begin());
  (void)DeserializeCompressed(compressed);

  ECPoint out;
  out.compressed_ = compressed;
  return out;
}

ECPoint ECPoint::GeneratorMultiply(const Scalar& scalar) {
  if (scalar.value() == 0) {
    TECDSA_THROW_ARGUMENT("Generator multiplication failed: scalar must be in [1, q-1]");
  }
  const EcPoint point = GetCurve().MulBase(ScalarToMpInt(scalar));
  if (GetCurve().IsInfinity(point)) {
    TECDSA_THROW_ARGUMENT("Generator multiplication failed: scalar must be in [1, q-1]");
  }

  ECPoint out;
  out.compressed_ = SerializeCompressed(point);
  return out;
}

ECPoint ECPoint::Add(const ECPoint& other) const {
  const EcPoint lhs = DeserializeCompressed(compressed_);
  const EcPoint rhs = DeserializeCompressed(other.compressed_);
  const EcPoint combined = GetCurve().Add(lhs, rhs);
  if (GetCurve().IsInfinity(combined)) {
    TECDSA_THROW_ARGUMENT("Point addition failed (sum is point at infinity?)");
  }

  ECPoint out;
  out.compressed_ = SerializeCompressed(combined);
  return out;
}

ECPoint ECPoint::Mul(const Scalar& scalar) const {
  if (scalar.value() == 0) {
    TECDSA_THROW_ARGUMENT("Point scalar multiplication failed");
  }
  const EcPoint point = DeserializeCompressed(compressed_);
  const EcPoint multiplied = GetCurve().Mul(point, ScalarToMpInt(scalar));
  if (GetCurve().IsInfinity(multiplied)) {
    TECDSA_THROW_ARGUMENT("Point scalar multiplication failed");
  }

  ECPoint out;
  out.compressed_ = SerializeCompressed(multiplied);
  return out;
}

Bytes ECPoint::ToCompressedBytes() const {
  return Bytes(compressed_.begin(), compressed_.end());
}

bool ECPoint::operator==(const ECPoint& other) const {
  return compressed_ == other.compressed_;
}

bool ECPoint::operator!=(const ECPoint& other) const {
  return !(*this == other);
}

}  // namespace tecdsa
