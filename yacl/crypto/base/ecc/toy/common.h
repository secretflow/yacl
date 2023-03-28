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

#include "yacl/crypto/base/ecc/group_sketch.h"

namespace yacl::crypto::toy {

static const std::string kLibName = "Toy";

struct CurveParam {
  MPInt A;
  MPInt B;
  AffinePoint G;
  MPInt p;
  MPInt n;
  MPInt h;

  CurveParam() = default;
};

// base class of Toy lib
class ToyEcGroup : public EcGroupSketch {
 public:
  ToyEcGroup(const CurveMeta &curve_meta, CurveParam param);

  MPInt GetCofactor() const override;
  MPInt GetField() const override;
  MPInt GetOrder() const override;
  EcPoint GetGenerator() const override;
  std::string GetLibraryName() const override;

  // Internal functions should not call this function since there is an extra
  // copy on AffinePoint
  AffinePoint GetAffinePoint(const EcPoint &point) const override;

  size_t HashPoint(const EcPoint &point) const override;

 protected:
  CurveParam params_;
};

}  // namespace yacl::crypto::toy
