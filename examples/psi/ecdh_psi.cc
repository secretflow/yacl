// Copyright 2023 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "examples/psi/ecdh_psi.h"

#include <memory>
#include <vector>

#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/link/link.h"
#include "yacl/secparam.h"

namespace examples::psi {

void EcdhPsi::MaskStrings(absl::Span<std::string> in,
                          absl::Span<yc::EcPoint> out) {
  YACL_ENFORCE(in.size() == out.size());
  for (size_t i = 0; i < in.size(); ++i) {
    out[i] = ec_->HashToCurve(yc::HashToCurveStrategy::Autonomous, in[i]);
    ec_->MulInplace(&out[i], sk_);
  }
}

void EcdhPsi::MaskEcPoints(absl::Span<yc::EcPoint> in,
                           absl::Span<std::string> out) {
  YACL_ENFORCE(in.size() == out.size());
  for (size_t i = 0; i < in.size(); ++i) {
    out[i] = ec_->SerializePoint(ec_->Mul(in[i], sk_));
  }
}

}  // namespace examples::psi
