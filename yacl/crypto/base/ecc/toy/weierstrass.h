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

#include "yacl/crypto/base/ecc/ecc_spi.h"

namespace yacl::crypto::toy {

struct WeierstrassCurveParam {
  MPInt A;
  MPInt B;
  AffinePoint G;
  MPInt p;
  MPInt n;
  MPInt h;

  WeierstrassCurveParam() = default;
};

// y^2 = x^3 + Ax + B
class ToyWeierstrassGroup : public EcGroup {
 public:
  static std::unique_ptr<EcGroup> Create(const CurveMeta &meta);
  static bool IsSupported(const CurveMeta &meta);

  std::string GetLibraryName() const override;

  MPInt GetCofactor() const override;
  MPInt GetField() const override;
  MPInt GetOrder() const override;
  EcPoint GetGenerator() const override;
  std::string ToString() override;

  EcPoint Add(const EcPoint &p1, const EcPoint &p2) const override;
  EcPoint Sub(const EcPoint &p1, const EcPoint &p2) const override;
  EcPoint Double(const EcPoint &p) const override;

  EcPoint MulBase(const MPInt &scalar) const override;
  EcPoint Mul(const MPInt &scalar, const EcPoint &point) const override;
  EcPoint MulDoubleBase(const MPInt &s1, const EcPoint &p1,
                        const MPInt &s2) const override;
  EcPoint Div(const EcPoint &point, const MPInt &scalar) const override;
  EcPoint Negate(const EcPoint &point) const override;
  AffinePoint GetAffinePoint(const EcPoint &point) const override;

  Buffer SerializePoint(const EcPoint &point,
                        PointOctetFormat format) const override;
  void SerializePoint(const EcPoint &point, PointOctetFormat format,
                      Buffer *buf) const override;
  EcPoint DeserializePoint(ByteContainerView buf,
                           PointOctetFormat format) const override;

  EcPoint HashToCurve(HashToCurveStrategy strategy,
                      std::string_view str) const override;
  bool PointEqual(const EcPoint &p1, const EcPoint &p2) const override;
  bool IsInCurveGroup(const EcPoint &point) const override;
  bool IsInfinity(const EcPoint &point) const override;
  bool IsInfinity(const AffinePoint &point) const;

 private:
  ToyWeierstrassGroup(const CurveMeta &curve_meta,
                      const WeierstrassCurveParam &param);
  AffinePoint Add(const AffinePoint &p1, const AffinePoint &p2) const;

  WeierstrassCurveParam params_;
};

}  // namespace yacl::crypto::toy
