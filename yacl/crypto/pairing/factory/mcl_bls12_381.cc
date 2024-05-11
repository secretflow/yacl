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

#include "yacl/crypto/pairing/factory/mcl_bls12_381.h"

namespace yacl::crypto {

MclPairingBls12381::MclPairingBls12381(const PairingMeta& meta,
                                       std::unique_ptr<EcGroup>& g1,
                                       std::unique_ptr<EcGroup>& g2,
                                       std::unique_ptr<GroupTarget>& gt)
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

std::shared_ptr<EcGroup> MclPairingBls12381::GetGroup1() const { return g1_; }

std::shared_ptr<EcGroup> MclPairingBls12381::GetGroup2() const { return g2_; }

std::shared_ptr<GroupTarget> MclPairingBls12381::GetGroupT() const {
  return gt_;
}

MPInt MclPairingBls12381::GetOrder() const { return g1_->GetOrder(); }

GtElement MclPairingBls12381::MillerLoop(const EcPoint& group1_point,
                                         const EcPoint& group2_point) const {
  mcl::bls12::GT ret;
  mcl::bls12::millerLoop(ret, *(CastAny<mcl::bls12::G1>(group1_point)),
                         *(CastAny<mcl::bls12::G2>(group2_point)));
  return ret;
}

GtElement MclPairingBls12381::FinalExp(const GtElement& x) const {
  mcl::bls12::GT ret;
  mcl::bls12::finalExp(ret, x.As<mcl::bls12::GT>());
  return ret;
}

GtElement MclPairingBls12381::Pairing(const EcPoint& group1_point,
                                      const EcPoint& group2_point) const {
  mcl::bls12::GT ret;
  mcl::bls12::pairing(ret, *(CastAny<mcl::bls12::G1>(group1_point)),
                      *(CastAny<mcl::bls12::G2>(group2_point)));
  return ret;
}

}  // namespace yacl::crypto
