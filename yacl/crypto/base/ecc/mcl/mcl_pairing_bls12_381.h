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

#include "mcl/bls12_381.hpp"

#include "yacl/crypto/base/ecc/mcl/mcl_ec_group.h"
#include "yacl/crypto/base/ecc/pairing_spi.h"
#include "yacl/crypto/base/field/mcl/mcl_field.h"

namespace yacl::crypto::hmcl {

using MclPairingBls12381G1 = MclGroupT<mcl::bls12::Fp, mcl::bls12::Fr>;
using MclPairingBls12381G2 = MclGroupT<mcl::bls12::Fp2, mcl::bls12::Fr>;
using MclPairingBls12381GT = MclField<mcl::bls12::GT, 12>;

class MclPairingBls12381 : public PairingGroup {
 public:
  PairingName GetPairingName() const override;
  PairingAlgorithm GetPairingAlgorithm() const override;
  std::string GetLibraryName() const override;
  std::string ToString() const override;
  size_t GetSecurityStrength() const override;

  std::shared_ptr<EcGroup> GetG1() const override;
  std::shared_ptr<EcGroup> GetG2() const override;
  std::shared_ptr<Field> GetGT() const override;

  MPInt GetOrder() const override;

  FElement MillerLoop(const EcPoint& group1_point,
                      const EcPoint& group2_point) const override;
  FElement FinalExp(const FElement& x) const override;
  // pairing = MillerLoop + FinalExponentiation
  FElement Pairing(const EcPoint& group1_point,
                   const EcPoint& group2_point) const override;

 private:
  PairingMeta meta_;
  std::shared_ptr<EcGroup> g1_;
  std::shared_ptr<EcGroup> g2_;
  std::shared_ptr<Field> gt_;

  friend class MclPGFactory;
  MclPairingBls12381(const PairingMeta& meta, std::unique_ptr<EcGroup>& g1,
                     std::unique_ptr<EcGroup>& g2, std::unique_ptr<Field>& gt);
};

}  // namespace yacl::crypto::hmcl
