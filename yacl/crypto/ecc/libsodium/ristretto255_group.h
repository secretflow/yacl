// Copyright 2024 Ant Group Co., Ltd.
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

#pragma once

#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/libsodium/sodium_group.h"

namespace yacl::crypto::sodium {

// Ristretto255 group implementation using libsodium's ristretto255 API.
// Unlike Ed25519, Ristretto255 has a prime-order group (cofactor = 1),
// making it suitable for protocols requiring prime-order groups like OPRF.
//
// Key differences from Ed25519:
// - Point storage: Array32 (32 bytes compressed) vs Array160 (extended coords)
// - Cofactor: 1 (prime-order) vs 8
// - libsodium API: crypto_core_ristretto255_* vs crypto_core_ed25519_*
class Ristretto255Group : public SodiumGroup {
 public:
  Ristretto255Group(const CurveMeta& meta, const CurveParam& param);

  // Returns the generator point
  EcPoint GetGenerator() const override;

  // Group operations
  EcPoint Add(const EcPoint& p1, const EcPoint& p2) const override;
  void AddInplace(EcPoint* p1, const EcPoint& p2) const override;

  EcPoint Sub(const EcPoint& p1, const EcPoint& p2) const override;
  void SubInplace(EcPoint* p1, const EcPoint& p2) const override;

  EcPoint Double(const EcPoint& p) const override;
  void DoubleInplace(EcPoint* p) const override;

  // Scalar multiplication
  EcPoint Mul(const EcPoint& point, const MPInt& scalar) const override;
  void MulInplace(EcPoint* point, const MPInt& scalar) const override;
  EcPoint MulBase(const MPInt& scalar) const override;
  EcPoint MulDoubleBase(const MPInt& s1, const MPInt& s2,
                        const EcPoint& p2) const override;

  // Negation
  EcPoint Negate(const EcPoint& point) const override;
  void NegateInplace(EcPoint* point) const override;

  // Point representation conversion
  AffinePoint GetAffinePoint(const EcPoint& point) const override;

  // Validation
  bool IsInCurveGroup(const EcPoint& point) const override;
  bool IsInfinity(const EcPoint& point) const override;

  // Override base class methods that assume Array160 format
  EcPoint CopyPoint(const EcPoint& point) const override;
  size_t HashPoint(const EcPoint& point) const override;
  bool PointEqual(const EcPoint& p1, const EcPoint& p2) const override;

  // Serialization (Ristretto255 uses 32-byte compressed format)
  uint64_t GetSerializeLength(PointOctetFormat format) const override;
  Buffer SerializePoint(const EcPoint& point,
                        PointOctetFormat format) const override;
  void SerializePoint(const EcPoint& point, PointOctetFormat format,
                      Buffer* buf) const override;
  void SerializePoint(const EcPoint& point, PointOctetFormat format,
                      uint8_t* buf, uint64_t buf_size) const override;
  EcPoint DeserializePoint(ByteContainerView buf,
                           PointOctetFormat format) const override;

  // Hash-to-Curve implementation (RFC 9380 compatible)
  EcPoint HashToCurve(HashToCurveStrategy strategy, std::string_view str,
                      std::string_view dst) const override;

  // Hash-to-Scalar for OPRF compatibility
  yacl::math::MPInt HashToScalar(HashToCurveStrategy strategy,
                                 std::string_view str,
                                 std::string_view dst) const override;

 private:
  // Convert MPInt to 32-byte little-endian array (modulo order n)
  // Returns true if the scalar is positive after mod, false otherwise
  bool MpIntToScalar(const MPInt& mp, unsigned char* buf) const;

  // Cast EcPoint to raw bytes (Ristretto255 uses Array32)
  static const unsigned char* CastBytes(const EcPoint& p);
  static unsigned char* CastBytes(EcPoint& p);

  EcPoint g_;    // Cached generator
  EcPoint inf_;  // Cached identity element
};

}  // namespace yacl::crypto::sodium
