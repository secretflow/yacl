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

#include "yacl/crypto/ecc/toy/common.h"

namespace yacl::crypto::toy {

// y^2 = x^3 + Ax + B
class ToyWeierstrassGroup : public ToyEcGroup {
 public:
  using ToyEcGroup::ToyEcGroup;

  std::string ToString() const override;

  EcPoint Add(const EcPoint &p1, const EcPoint &p2) const override;

  EcPoint Mul(const EcPoint &point, const MPInt &scalar) const override;
  EcPoint Negate(const EcPoint &point) const override;

  uint64_t GetSerializeLength(PointOctetFormat format) const override;
  Buffer SerializePoint(const EcPoint &point,
                        PointOctetFormat format) const override;
  void SerializePoint(const EcPoint &point, PointOctetFormat format,
                      Buffer *buf) const override;
  void SerializePoint(const EcPoint &point, PointOctetFormat format,
                      uint8_t *buf, uint64_t buf_size) const override;
  EcPoint DeserializePoint(ByteContainerView buf,
                           PointOctetFormat format) const override;

  EcPoint HashToCurve(HashToCurveStrategy strategy,
                      std::string_view str) const override;
  bool PointEqual(const EcPoint &p1, const EcPoint &p2) const override;
  bool IsInCurveGroup(const EcPoint &point) const override;
  bool IsInfinity(const EcPoint &point) const override;
  bool IsInfinity(const AffinePoint &point) const;

 private:
  AffinePoint Add(const AffinePoint &p1, const AffinePoint &p2) const;
};

}  // namespace yacl::crypto::toy
