// Copyright 2025 @yangjucai.
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

#include "yacl/crypto/experimental/zkp/bulletproofs/ipa/inner_product_proof.h"

namespace examples::zkp {

class R1CSProof {
 public:
  // Phase 1 commitments
  yacl::crypto::EcPoint A_I1;
  yacl::crypto::EcPoint A_O1;
  yacl::crypto::EcPoint S1;
  // Phase 2 commitments
  yacl::crypto::EcPoint A_I2;
  yacl::crypto::EcPoint A_O2;
  yacl::crypto::EcPoint S2;
  // Commitments to t coefficients
  yacl::crypto::EcPoint T_1;
  yacl::crypto::EcPoint T_3;
  yacl::crypto::EcPoint T_4;
  yacl::crypto::EcPoint T_5;
  yacl::crypto::EcPoint T_6;
  // Proof scalars
  yacl::math::MPInt t_x;
  yacl::math::MPInt t_x_blinding;
  yacl::math::MPInt e_blinding;
  // Inner product proof
  InnerProductProof ipp_proof;

  // Serialization
  yacl::Buffer ToBytes(const std::shared_ptr<yacl::crypto::EcGroup>& curve) const;
  static R1CSProof FromBytes(const yacl::ByteContainerView& bytes,
                             const std::shared_ptr<yacl::crypto::EcGroup>& curve);

 private:
  bool MissingPhase2Commitments(const std::shared_ptr<yacl::crypto::EcGroup>& curve) const;
};

} // namespace examples::zkp