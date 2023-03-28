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

#include "yacl/crypto/base/ecc/toy/common.h"

#include <utility>

namespace yacl::crypto::toy {

ToyEcGroup::ToyEcGroup(const CurveMeta &curve_meta, CurveParam param)
    : EcGroupSketch(curve_meta), params_(std::move(param)) {}

std::string ToyEcGroup::GetLibraryName() const { return kLibName; }

MPInt ToyEcGroup::GetCofactor() const { return params_.h; }
MPInt ToyEcGroup::GetField() const { return params_.p; }
MPInt ToyEcGroup::GetOrder() const { return params_.n; }

EcPoint ToyEcGroup::GetGenerator() const { return params_.G; }

AffinePoint ToyEcGroup::GetAffinePoint(const EcPoint &point) const {
  return std::get<AffinePoint>(point);
}

size_t ToyEcGroup::HashPoint(const EcPoint &point) const {
  return std::get<AffinePoint>(point).HashCode();
}

}  // namespace yacl::crypto::toy
