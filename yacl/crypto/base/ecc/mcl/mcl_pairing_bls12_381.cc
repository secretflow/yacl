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

#include "yacl/crypto/base/ecc/mcl/mcl_pairing_bls12_381.h"

namespace yacl::crypto::hmcl {

MclPairingBls12381::MclPairingBls12381(const PairingMeta& meta,
                                       std::unique_ptr<EcGroup>& g1,
                                       std::unique_ptr<EcGroup>& g2,
                                       std::unique_ptr<Field>& gt)
    : meta_(meta) {
  g1_ = std::move(g1);
  g2_ = std::move(g2);
  gt_ = std::move(gt);
}

std::string MclPairingBls12381::GetLibraryName() const { return kLibName; }

PairingName MclPairingBls12381::GetPairingName() const { return meta_.name; }

PairingAlgorithm MclPairingBls12381::GetPairingAlgorithm() const {
  return PairingAlgorithm::Ate;
}
std::string MclPairingBls12381::ToString() const { return GetPairingName(); }

size_t MclPairingBls12381::GetSecurityStrength() const {
  return meta_.secure_bits;
}

std::shared_ptr<EcGroup> MclPairingBls12381::GetG1() const { return g1_; }

std::shared_ptr<EcGroup> MclPairingBls12381::GetG2() const { return g2_; }

std::shared_ptr<Field> MclPairingBls12381::GetGT() const { return gt_; }

MPInt MclPairingBls12381::GetOrder() const { return g1_->GetOrder(); }

FElement MclPairingBls12381::MillerLoop(const EcPoint& group1_point,
                                        const EcPoint& group2_point) const {
  FElement ret = gt_->MakeInstance();
  mcl::bls12::millerLoop(*(CastAny<mcl::bls12::GT>(ret)),
                         *(CastAny<mcl::bls12::G1>(group1_point)),
                         *(CastAny<mcl::bls12::G2>(group2_point)));
  return ret;
}

FElement MclPairingBls12381::FinalExp(const FElement& x) const {
  FElement ret = gt_->MakeInstance();
  mcl::bls12::finalExp(*(CastAny<mcl::bls12::GT>(ret)),
                       *(CastAny<mcl::bls12::GT>(x)));
  return ret;
}

FElement MclPairingBls12381::Pairing(const EcPoint& group1_point,
                                     const EcPoint& group2_point) const {
  FElement ret = gt_->MakeInstance();
  mcl::bls12::pairing(*(CastAny<mcl::bls12::GT>(ret)),
                      *(CastAny<mcl::bls12::G1>(group1_point)),
                      *(CastAny<mcl::bls12::G2>(group2_point)));
  return ret;
}

}  // namespace yacl::crypto::hmcl
