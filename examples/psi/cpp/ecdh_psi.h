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

namespace examples::psi {

// An example of PSI protocol
//
// NOTE: this PSI protocol is designed solely for demonstration and is not
// ready, or designed for production use, please do not use this in production.
//
// NOTE: we recommend user to use https://github.com/secretflow/psi
//
class EcdhPsi {
 public:
  EcdhPsi() {
    // Use FourQ curve
    ec_ = yacl::crypto::EcGroupFactory::Instance().Create(
        /* curve name */ "FourQ");

    // Generate random key
    yacl::crypto::MPInt::RandomLtN(ec_->GetOrder(), &sk_);
  }

  explicit EcdhPsi(const yacl::crypto::MPInt& sk) { sk_ = sk; }

  // Mask input strings with secret key, and outputs the EcPoint results
  void MaskStrings(absl::Span<std::string> in,
                   absl::Span<yacl::crypto::EcPoint> out) const;

  // Mask input EcPoints with secret key, and outputs the serialized
  // EcPoint strings
  void MaskEcPointsAndHashToU128(absl::Span<yacl::crypto::EcPoint> in,
                                 absl::Span<uint128_t> out) const;

  // ----------------------------
  // Extra functions (for Python)
  // ----------------------------

  // Mask input strings with secret key, and outputs the EcPoint results
  std::vector<std::string> MaskStringsEx(std::vector<std::string> in) const;

  // Mask input strings with secret key, and outputs the EcPoint results
  std::vector<uint128_t> MaskEcPointsAndHashToU128Ex(
      std::vector<std::string> in) const;

  std::shared_ptr<yacl::crypto::EcGroup> GetGroup() const { return ec_; }

 private:
  yacl::crypto::MPInt sk_;                     // secret key
  std::shared_ptr<yacl::crypto::EcGroup> ec_;  // ec group
};

}  // namespace examples::psi
