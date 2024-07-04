// Copyright 2024 Guowei Ling.
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

#include "examples/hesm2/public_key.h"

#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/math/mpint/mp_int.h"

namespace examples::hesm2 {

class PrivateKey {
 public:
  explicit PrivateKey(std::shared_ptr<yacl::crypto::EcGroup> ec_group)
      : ec_group_(ec_group), public_key_(ec_group_->GetGenerator(), ec_group_) {
    Initialize();
  }

  const yacl::math::MPInt& GetK() const { return k_; }
  const PublicKey& GetPublicKey() const { return public_key_; }
  std::shared_ptr<yacl::crypto::EcGroup> GetEcGroup() const {
    return ec_group_;
  }

 private:
  void Initialize() {
    yacl::math::MPInt k;
    yacl::math::MPInt::RandomLtN(ec_group_->GetOrder(), &k);
    public_key_ = GeneratePublicKey();
  }

  PublicKey GeneratePublicKey() const {
    auto generator = ec_group_->GetGenerator();
    auto point = ec_group_->Mul(generator, k_);
    return {point, ec_group_};
  }

  std::shared_ptr<yacl::crypto::EcGroup> ec_group_;
  yacl::math::MPInt k_;
  PublicKey public_key_;
};
}  // namespace examples::hesm2