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

#include "yacl/crypto/pairing/factory/mcl_pairing_group.h"

namespace yacl::crypto {

template <typename G1_, typename G2_, typename GT_>
std::string MclPairingGroup<G1_, G2_, GT_>::GetLibraryName() const {
  return kLibName;
}

template <typename G1_, typename G2_, typename GT_>
PairingName MclPairingGroup<G1_, G2_, GT_>::GetPairingName() const {
  return meta_.name;
}

template <typename G1_, typename G2_, typename GT_>
PairingAlgorithm MclPairingGroup<G1_, G2_, GT_>::GetPairingAlgorithm() const {
  return PairingAlgorithm::Ate;
}

template <typename G1_, typename G2_, typename GT_>
std::string MclPairingGroup<G1_, G2_, GT_>::ToString() const {
  return GetPairingName();
}

template <typename G1_, typename G2_, typename GT_>
size_t MclPairingGroup<G1_, G2_, GT_>::GetSecurityStrength() const {
  return meta_.secure_bits;
}

template <typename G1_, typename G2_, typename GT_>
std::shared_ptr<EcGroup> MclPairingGroup<G1_, G2_, GT_>::GetGroup1() const {
  return g1_;
}

template <typename G1_, typename G2_, typename GT_>
std::shared_ptr<EcGroup> MclPairingGroup<G1_, G2_, GT_>::GetGroup2() const {
  return g2_;
}

template <typename G1_, typename G2_, typename GT_>
std::shared_ptr<GroupTarget> MclPairingGroup<G1_, G2_, GT_>::GetGroupT() const {
  return gt_;
}

template <typename G1_, typename G2_, typename GT_>
MPInt MclPairingGroup<G1_, G2_, GT_>::GetOrder() const {
  return g1_->GetOrder();
}

template <typename G1_, typename G2_, typename GT_>
GtElement MclPairingGroup<G1_, G2_, GT_>::MillerLoop(
    const EcPoint& group1_point, const EcPoint& group2_point) const {
  GT_ ret;
  miller_func_(ret, *(CastAny<G1_>(group1_point)),
               *(CastAny<G2_>(group2_point)));
  return ret;
}

template <typename G1_, typename G2_, typename GT_>
GtElement MclPairingGroup<G1_, G2_, GT_>::FinalExp(const GtElement& x) const {
  GT_ ret;
  final_exp_func_(ret, x.As<GT_>());
  return ret;
}

template <typename G1_, typename G2_, typename GT_>
GtElement MclPairingGroup<G1_, G2_, GT_>::Pairing(
    const EcPoint& group1_point, const EcPoint& group2_point) const {
  GT_ ret;
  pairing_func_(ret, *(CastAny<G1_>(group1_point)),
                *(CastAny<G2_>(group2_point)));
  return ret;
}

template <typename G1_, typename G2_, typename GT_>
MclPairingGroup<G1_, G2_, GT_>::MclPairingGroup(
    const PairingMeta& meta, std::unique_ptr<EcGroup>& g1,
    std::unique_ptr<EcGroup>& g2, std::unique_ptr<GroupTarget>& gt)
    : meta_(meta) {
  g1_ = std::move(g1);
  g2_ = std::move(g2);
  gt_ = std::move(gt);
}

#define TEMPLATE_PARING_INSTANCE(classname, curve_name)                    \
  template class MclPairingGroup<mcl::curve_name::G1, mcl::curve_name::G2, \
                                 mcl::curve_name::GT>;

// Pairing Group Classes
// TEMPLATE_PARING_INSTANCE(Bls12381, bls12);
TEMPLATE_PARING_INSTANCE(BNSnark, bnsnark);

#ifdef MCL_ALL_PAIRING_FOR_YACL
TEMPLATE_PARING_INSTANCE(BN254, bn254);
TEMPLATE_PARING_INSTANCE(BN384M, bn382m);
TEMPLATE_PARING_INSTANCE(BN384R, bn382r);
TEMPLATE_PARING_INSTANCE(BN462, bn462);
TEMPLATE_PARING_INSTANCE(BN160, bn160);
TEMPLATE_PARING_INSTANCE(Bls12377, bls123);
TEMPLATE_PARING_INSTANCE(Bls12461, bls124);
TEMPLATE_PARING_INSTANCE(BN256, bn256);
#endif

}  // namespace yacl::crypto
