// Copyright 2024 Ant Group Co., Ltd.
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

#include "pybind11/complex.h"
#include "pybind11/functional.h"
#include "pybind11/pybind11.h"
#include "pybind11/stl.h"
#include "pybind11/typing.h"

#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/crypto/hash/hash_utils.h"

namespace py = pybind11;
namespace yc = yacl::crypto;

namespace examples::psi {

// An example of PSI protocol
//
// NOTE: this PSI protocol is designed solely for demonstation and is not
// ready, or designed for production use, please do not use this in
// production.
//
// NOTE: we recommend user to use https://github.com/secretflow/psi
//
class EcdhPsiPy {
 public:
  EcdhPsiPy() {
    // Use FourQ curve
    ec_ = yacl::crypto::EcGroupFactory::Instance().Create(
        /* curve name */ "FourQ");

    // Generate random key
    yacl::crypto::MPInt::RandomLtN(ec_->GetOrder(), &sk_);
  }

  explicit EcdhPsiPy(const yacl::crypto::MPInt& sk) { sk_ = sk; }

  // Mask input strings with secret key, and outputs the EcPoint results
  std::vector<py::bytes> MaskStrings(std::vector<std::string> in) const {
    YACL_ENFORCE(!in.empty());
    std::vector<py::bytes> out(in.size());
    for (size_t i = 0; i < in.size(); ++i) {
      auto temp = ec_->HashToCurve(yc::HashToCurveStrategy::Autonomous, in[i]);
      ec_->MulInplace(&temp, sk_);
      out[i] = py::bytes(std::string(ec_->SerializePoint(temp)));
    }
    return out;
  }

  // Mask input strings with secret key, and outputs the EcPoint results
  std::vector<uint128_t> MaskEcPointsAndHashToU128(
      std::vector<std::string> in) const {
    YACL_ENFORCE(!in.empty());
    std::vector<uint128_t> out(in.size());
    for (size_t i = 0; i < in.size(); ++i) {
      auto temp = ec_->DeserializePoint(in[i]);
      out[i] = yc::Blake3_128(ec_->SerializePoint(ec_->Mul(temp, sk_)));
    }
    return out;
  }

 private:
  yacl::crypto::MPInt sk_;                     // secret key
  std::shared_ptr<yacl::crypto::EcGroup> ec_;  // ec group
};

}  // namespace examples::psi
