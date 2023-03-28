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

namespace yacl::crypto {

class EcGroupSketch : public EcGroup {
 public:
  //================================//
  // Elliptic curve meta info query //
  //================================//

  CurveName GetCurveName() const override { return meta_.name; }
  CurveForm GetCurveForm() const override { return meta_.form; }
  FieldType GetFieldType() const override { return meta_.field_type; }
  size_t GetSecurityStrength() const override { return meta_.secure_bits; }

  //================================//
  //   Elliptic curve computation   //
  //================================//

  void AddInplace(EcPoint *p1, const EcPoint &p2) const override;

  EcPoint Sub(const EcPoint &p1, const EcPoint &p2) const override;
  void SubInplace(EcPoint *p1, const EcPoint &p2) const override;

  EcPoint Double(const EcPoint &p) const override;
  void DoubleInplace(EcPoint *p) const override;

  EcPoint MulBase(const MPInt &scalar) const override;
  void MulInplace(EcPoint *point, const MPInt &scalar) const override;
  EcPoint MulDoubleBase(const MPInt &s1, const MPInt &s2,
                        const EcPoint &p2) const override;
  EcPoint Div(const EcPoint &point, const MPInt &scalar) const override;

  void DivInplace(EcPoint *point, const MPInt &scalar) const override;

  void NegateInplace(EcPoint *point) const override;

 protected:
  explicit EcGroupSketch(CurveMeta meta) : meta_(std::move(meta)) {}

  CurveMeta meta_;
};

}  // namespace yacl::crypto
