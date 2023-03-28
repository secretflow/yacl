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

#include "yacl/crypto/base/ecc/toy/common.h"

namespace yacl::crypto::toy {

// RFC 7748 (Elliptic Curves for Security) implementation
// https://tools.ietf.org/html/rfc7748
// https://www.rfc-editor.org/errata_search.php?rfc=7748
//
// Only used in ECDH scenarios
// XGroup only use X-coordinates of points
class ToyXGroup : public ToyEcGroup {
 public:
  ToyXGroup(const CurveMeta &curve_meta, const CurveParam &param);

  std::string ToString() override;

  // Add is not supported, since only the x coordinate cannot uniquely determine
  // a point
  EcPoint Add(const EcPoint &p1, const EcPoint &p2) const override;
  EcPoint Mul(const EcPoint &point, const MPInt &scalar) const override;
  EcPoint Negate(const EcPoint &point) const override;

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

 private:
  MPInt a24_;
};

}  // namespace yacl::crypto::toy
