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

// Ristretto255: prime-order group (cofactor=1) from Curve25519, uses Array32.
class Ristretto255Group : public SodiumGroup {
 public:
  Ristretto255Group(const CurveMeta& meta, const CurveParam& param);

  EcPoint GetGenerator() const override;

  EcPoint Add(const EcPoint& p1, const EcPoint& p2) const override;
  void AddInplace(EcPoint* p1, const EcPoint& p2) const override;
  EcPoint Sub(const EcPoint& p1, const EcPoint& p2) const override;
  void SubInplace(EcPoint* p1, const EcPoint& p2) const override;
  EcPoint Double(const EcPoint& p) const override;
  void DoubleInplace(EcPoint* p) const override;

  EcPoint Mul(const EcPoint& point, const MPInt& scalar) const override;
  void MulInplace(EcPoint* point, const MPInt& scalar) const override;
  EcPoint MulBase(const MPInt& scalar) const override;
  EcPoint MulDoubleBase(const MPInt& s1, const MPInt& s2,
                        const EcPoint& p2) const override;

  EcPoint Negate(const EcPoint& point) const override;
  void NegateInplace(EcPoint* point) const override;

  AffinePoint GetAffinePoint(const EcPoint& point) const override;
  bool IsInCurveGroup(const EcPoint& point) const override;
  bool IsInfinity(const EcPoint& point) const override;

  EcPoint CopyPoint(const EcPoint& point) const override;
  size_t HashPoint(const EcPoint& point) const override;
  bool PointEqual(const EcPoint& p1, const EcPoint& p2) const override;

  uint64_t GetSerializeLength(PointOctetFormat format) const override;
  Buffer SerializePoint(const EcPoint& point,
                        PointOctetFormat format) const override;
  void SerializePoint(const EcPoint& point, PointOctetFormat format,
                      Buffer* buf) const override;
  void SerializePoint(const EcPoint& point, PointOctetFormat format,
                      uint8_t* buf, uint64_t buf_size) const override;
  EcPoint DeserializePoint(ByteContainerView buf,
                           PointOctetFormat format) const override;

  EcPoint HashToCurve(HashToCurveStrategy strategy, std::string_view str,
                      std::string_view dst) const override;
  yacl::math::MPInt HashToScalar(HashToCurveStrategy strategy,
                                 std::string_view str,
                                 std::string_view dst) const override;

 private:
  void MpIntToScalar(const MPInt& mp, unsigned char* buf) const;
  static const unsigned char* CastBytes(const EcPoint& p);
  static unsigned char* CastBytes(EcPoint& p);

  EcPoint g_;
  EcPoint inf_;
};

}  // namespace yacl::crypto::sodium
