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

#include "psi/cpp/ecdh_psi.h"

#include <memory>
#include <vector>

#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/link/link.h"
#include "yacl/secparam.h"

namespace yc = yacl::crypto;

namespace examples::psi {

void EcdhPsi::MaskStrings(absl::Span<std::string> in,
                          absl::Span<yc::EcPoint> out) const {
  YACL_ENFORCE(!in.empty());
  YACL_ENFORCE(in.size() == out.size());
  for (size_t i = 0; i < in.size(); ++i) {
    out[i] = ec_->HashToCurve(yc::HashToCurveStrategy::Autonomous, in[i]);
    ec_->MulInplace(&out[i], sk_);
  }
}

void EcdhPsi::MaskEcPointsAndHashToU128(absl::Span<yc::EcPoint> in,
                                        absl::Span<uint128_t> out) const {
  YACL_ENFORCE(!in.empty());
  YACL_ENFORCE(in.size() == out.size());
  for (size_t i = 0; i < in.size(); ++i) {
    out[i] = yc::Blake3_128(ec_->SerializePoint(ec_->Mul(in[i], sk_)));
  }
}

// Mask input strings with secret key, and outputs the EcPoint results
std::vector<std::string> EcdhPsi::MaskStringsEx(
    std::vector<std::string> in) const {
  YACL_ENFORCE(!in.empty());
  std::vector<std::string> out(in.size());
  for (size_t i = 0; i < in.size(); ++i) {
    auto temp = ec_->HashToCurve(yc::HashToCurveStrategy::Autonomous, in[i]);
    ec_->MulInplace(&temp, sk_);
    out[i] = ec_->SerializePoint(temp);
  }
  return out;
}

// Mask input strings with secret key, and outputs the EcPoint results
std::vector<uint128_t> EcdhPsi::MaskEcPointsAndHashToU128Ex(
    std::vector<std::string> in) const {
  YACL_ENFORCE(!in.empty());
  std::vector<uint128_t> out(in.size());
  for (size_t i = 0; i < in.size(); ++i) {
    auto temp = ec_->DeserializePoint(in[i]);
    out[i] = yc::Blake3_128(ec_->SerializePoint(ec_->Mul(temp, sk_)));
  }
  return out;
}
}  // namespace examples::psi
