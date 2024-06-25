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

#pragma once

#include <memory>
#include <vector>

#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/link/link.h"
#include "yacl/secparam.h"

namespace examples::psi {

namespace yc = yacl::crypto;

// An example of PSI protocol
//
// NOTE: this PSI protocol is designed solely for demonstation and is not ready,
// or designed for production use, please do not use this in production.
//
// NOTE: we recommend user to use https://github.com/secretflow/psi
//
class EcdhPsi {
 public:
  EcdhPsi() {
    // Use FourQ curve
    ec_ = yc::EcGroupFactory::Instance().Create(/* curve name */ "FourQ");

    // Generate random key
    yc::MPInt::RandomLtN(ec_->GetOrder(), &sk_);
  }

  // Mask input strings with secret key, and outputs the EcPoint results
  void MaskStrings(absl::Span<std::string> in, absl::Span<yc::EcPoint> out);

  // Mask input EcPoints with secret key, and outputs the serialized
  // EcPoint strings
  void MaskEcPoints(absl::Span<yc::EcPoint> in, absl::Span<std::string> out);

 private:
  yc::MPInt sk_;                     // secret key
  std::shared_ptr<yc::EcGroup> ec_;  // ec group
};

}  // namespace examples::psi
