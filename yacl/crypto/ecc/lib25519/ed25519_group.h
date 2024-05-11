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

#include "yacl/crypto/ecc/lib25519/lib25519_group.h"

namespace yacl::crypto::lib25519 {

class Ed25519Group : public Lib25519Group {
 public:
  Ed25519Group(const CurveMeta& meta, const CurveParam& param);
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

 private:
  bool MPInt2Scalar(const MPInt& mp, sc25519* scalar) const;

  EcPoint g_;
  EcPoint inf_;
};

}  // namespace yacl::crypto::lib25519
