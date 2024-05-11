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

#include "yacl/crypto/ecc/mcl/mcl_ec_group.h"
#include "yacl/crypto/pairing/factory/mcl_bls12_381.h"
#include "yacl/crypto/pairing/factory/mcl_pairing_header.h"
#include "yacl/crypto/pairing/factory/pairing_spi.h"
#include "yacl/math/galois_field/factory/mcl_factory.h"

namespace yacl::crypto {

class MclPGFactory {
 public:
  static std::unique_ptr<PairingGroup> Create(const PairingMeta& meta);
  // For non-standard pairing curve supported by libmcl
  static std::unique_ptr<PairingGroup> CreateByName(const PairingName& name);
  static PairingMeta GetMeta(const PairingName& name);
  static bool IsSupported(const PairingMeta& meta);
};

// Pairing Classes Alias
#define PAIRING_CURVE_ALIAS(classname, curve_name)          \
  using MclPairing##classname##G1 =                         \
      MclGroupT<mcl::curve_name::Fp, mcl::curve_name::Fr>;  \
  using MclPairing##classname##G2 =                         \
      MclGroupT<mcl::curve_name::Fp2, mcl::curve_name::Fr>; \
  using MclPairing##classname##GT = math::MclField<mcl::curve_name::GT, 12>;

PAIRING_CURVE_ALIAS(BNSnark, bnsnark);
#ifdef MCL_ALL_PAIRING_FOR_YACL
PAIRING_CURVE_ALIAS(BN254, bn254);
PAIRING_CURVE_ALIAS(BN384M, bn382m);
PAIRING_CURVE_ALIAS(BN384R, bn382r);
PAIRING_CURVE_ALIAS(BN462, bn462);
PAIRING_CURVE_ALIAS(BN160, bn160);
PAIRING_CURVE_ALIAS(Bls12377, bls123);
PAIRING_CURVE_ALIAS(Bls12461, bls124);
PAIRING_CURVE_ALIAS(BN256, bn256);
#endif

// Warning! Pairing group in libmcl only support one instance at the same
// moment.
template <typename G1_, typename G2_, typename GT_>
class MclPairingGroup : public PairingGroup {
 public:
  std::string GetLibraryName() const override;
  PairingName GetPairingName() const override;
  PairingAlgorithm GetPairingAlgorithm() const override;
  std::string ToString() const override;
  size_t GetSecurityStrength() const override;

  std::shared_ptr<EcGroup> GetGroup1() const override;
  std::shared_ptr<EcGroup> GetGroup2() const override;
  std::shared_ptr<GroupTarget> GetGroupT() const override;

  MPInt GetOrder() const override;

  GtElement MillerLoop(const EcPoint& group1_point,
                       const EcPoint& group2_point) const override;
  GtElement FinalExp(const GtElement& x) const override;
  GtElement Pairing(const EcPoint& group1_point,
                    const EcPoint& group2_point) const override;

 private:
  using PairingFunc = std::function<void(GT_&, const G1_&, const G2_&)>;
  using MillerFunc = std::function<void(GT_&, const G1_&, const G2_&)>;
  using FinalExpFunc = std::function<void(GT_&, const GT_&)>;

  PairingMeta meta_;
  std::shared_ptr<EcGroup> g1_;
  std::shared_ptr<EcGroup> g2_;
  std::shared_ptr<GroupTarget> gt_;

  PairingFunc pairing_func_;
  MillerFunc miller_func_;
  FinalExpFunc final_exp_func_;

  friend class MclPGFactory;

 public:
  explicit MclPairingGroup(const PairingMeta& meta,
                           std::unique_ptr<EcGroup>& g1,
                           std::unique_ptr<EcGroup>& g2,
                           std::unique_ptr<GroupTarget>& gt);
};

#define PAIRING_GROUP_ALIAS(classname, namespace_name)                  \
  using MclPairing##classname =                                         \
      MclPairingGroup<mcl::namespace_name::G1, mcl::namespace_name::G2, \
                      mcl::namespace_name::GT>;

// Pairing Group Classes
PAIRING_GROUP_ALIAS(BNSnark, bnsnark);
#ifdef MCL_ALL_PAIRING_FOR_YACL
PAIRING_GROUP_ALIAS(BN254, bn254);
PAIRING_GROUP_ALIAS(BN384M, bn382m);
PAIRING_GROUP_ALIAS(BN384R, bn382r);
PAIRING_GROUP_ALIAS(BN462, bn462);
PAIRING_GROUP_ALIAS(BN160, bn160);
PAIRING_GROUP_ALIAS(Bls12377, bls123);
PAIRING_GROUP_ALIAS(Bls12461, bls124);
PAIRING_GROUP_ALIAS(BN256, bn256);
#endif

}  // namespace yacl::crypto
