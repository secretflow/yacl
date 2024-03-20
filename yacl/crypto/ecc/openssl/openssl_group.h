// Copyright 2023 Ant Group Co., Ltd.
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

#include <memory>
#include <string>

#include "yacl/crypto/ecc/group_sketch.h"
#include "yacl/crypto/openssl_wrappers.h"

namespace yacl::crypto::openssl {

class OpensslGroup : public EcGroupSketch {
 public:
  static std::unique_ptr<EcGroup> Create(const CurveMeta& meta);
  static bool IsSupported(const CurveMeta& meta);

  std::string GetLibraryName() const override;

  MPInt GetCofactor() const override;
  MPInt GetField() const override;
  MPInt GetOrder() const override;
  EcPoint GetGenerator() const override;
  std::string ToString() const override;

  EcPoint Add(const EcPoint& p1, const EcPoint& p2) const override;
  void AddInplace(EcPoint* p1, const EcPoint& p2) const override;

  EcPoint Double(const EcPoint& p) const override;
  void DoubleInplace(EcPoint* p) const override;

  EcPoint Mul(const EcPoint& point, const MPInt& scalar) const override;
  void MulInplace(EcPoint* point, const MPInt& scalar) const override;

  EcPoint MulBase(const MPInt& scalar) const override;
  EcPoint MulDoubleBase(const MPInt& s1, const MPInt& s2,
                        const EcPoint& p2) const override;

  EcPoint Negate(const EcPoint& point) const override;
  void NegateInplace(EcPoint* point) const override;

  // Copy or Convert: AffinePoint -> EcPoint(OpensslPoint)
  EcPoint CopyPoint(const EcPoint& point) const override;

  // EcPoint(OpensslPoint) -> AffinePoint
  AffinePoint GetAffinePoint(const EcPoint& point) const override;

  uint64_t GetSerializeLength(PointOctetFormat format) const override;

  Buffer SerializePoint(const EcPoint& point,
                        PointOctetFormat format) const override;
  void SerializePoint(const EcPoint& point, PointOctetFormat format,
                      Buffer* buf) const override;
  void SerializePoint(const EcPoint& point, PointOctetFormat format,
                      uint8_t* buf, uint64_t buf_size) const override;
  EcPoint DeserializePoint(ByteContainerView buf,
                           PointOctetFormat format) const override;

  EcPoint HashToCurve(HashToCurveStrategy strategy,
                      std::string_view str) const override;

  size_t HashPoint(const EcPoint& point) const override;
  bool PointEqual(const EcPoint& p1, const EcPoint& p2) const override;
  bool IsInCurveGroup(const EcPoint& point) const override;
  bool IsInfinity(const EcPoint& point) const override;

 private:
  explicit OpensslGroup(const CurveMeta& meta, UniqueEcGroup group);

  AnyPtr MakeOpensslPoint() const;

  UniqueEcGroup group_;
  UniqueBn field_p_;

  MPInt order_;
  MPInt cofactor_;
  EcPoint generator_;

  static thread_local UniqueBnCtx ctx_;
};

}  // namespace yacl::crypto::openssl
