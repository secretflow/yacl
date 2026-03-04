#pragma once

#include <array>
#include <cstdint>
#include <span>

#include "yacl/crypto/experimental/threshold_ecdsa/common/bytes.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/scalar.h"

namespace tecdsa {

class ECPoint {
 public:
  ECPoint();

  static ECPoint FromCompressed(std::span<const uint8_t> compressed_bytes);
  static ECPoint GeneratorMultiply(const Scalar& scalar);

  ECPoint Add(const ECPoint& other) const;
  ECPoint Mul(const Scalar& scalar) const;

  Bytes ToCompressedBytes() const;

  bool operator==(const ECPoint& other) const;
  bool operator!=(const ECPoint& other) const;

 private:
  std::array<uint8_t, 33> compressed_{};
};

}  // namespace tecdsa
