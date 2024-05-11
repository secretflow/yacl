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

#include "absl/strings/ascii.h"

#include "yacl/crypto/pairing/factory/mcl_pairing_group.h"

namespace yacl::crypto {

std::map<PairingName, int> Name2MclPairingEnum = {
    {"bls12-381", MCL_BLS12_381}, {"bn_snark1", MCL_BN_SNARK1},
#ifdef MCL_ALL_PAIRING_FOR_YACL
    {"bn254", MCL_BN254},         {"bn382m", MCL_BN381_1},
    {"bn382r", MCL_BN381_2},      {"bn462", MCL_BN462},
    {"bn160", MCL_BN160},         {"bls12-461", MCL_BLS12_461},
    {"bn256", MCL_BN_P256},
#endif
    // not supported yet, under construction by libmcl
    // {"bls12-377", MCL_BLS12_377},
};

PairingMeta MclPGFactory::GetMeta(const PairingName& name) {
  PairingMeta meta = GetCurveMetaByName("bls12-381");
  meta.name = absl::AsciiStrToLower(name);

  auto pairing_type = Name2MclPairingEnum.at(meta.name);
  switch (pairing_type) {
    case MCL_BLS12_381:
      break;
    case MCL_BN_SNARK1: {
      meta.secure_bits = 100;
      break;
    }
#ifdef MCL_ALL_PAIRING_FOR_YACL
    case MCL_BLS12_461:
    case MCL_BN381_1:
    case MCL_BN462:
    case MCL_BN381_2: {
      meta.secure_bits = 128;
      break;
    }
    case MCL_BN254:
    case MCL_BN_P256: {
      meta.secure_bits = 100;
      break;
    }
    case MCL_BN160: {
      // https://github.com/herumi/mcl/issues/28#issuecomment-415266323
      meta.secure_bits = 70;
      break;
    }
#endif
    // case MCL_BLS12_377: {
    //   meta = GetCurveMetaByName("bls12-377");
    //   break;
    // }
    default:
      YACL_THROW("Not supported pairing {} in {}!", meta.LowerName(), kLibName);
  }
  return meta;
}

std::unique_ptr<PairingGroup> MclPGFactory::CreateByName(
    const PairingName& name) {
  return Create(GetMeta(name));
}

#define CASE_DEFINE(mcl_pairing_macro, class_name, namespace_name)           \
  case MCL_##mcl_pairing_macro: {                                            \
    auto p1 = std::make_shared<MclPairing##class_name##G1::Ec>();            \
    auto p2 = std::make_shared<MclPairing##class_name##G2::Ec>();            \
    static bool once = [&] {                                                 \
      mcl::namespace_name::initPairing(mcl::mcl_pairing_macro);              \
      return true;                                                           \
    }();                                                                     \
    mcl::namespace_name::hashAndMapToG1(*p1, #class_name);                   \
    mcl::namespace_name::hashAndMapToG2(*p2, #class_name);                   \
    YACL_ENFORCE(once && !p1->isZero() && !p2->isZero());                    \
                                                                             \
    auto g1 = std::unique_ptr<EcGroup>(new MclPairing##class_name##G1(       \
        meta, pairing_type, AnyPtr(p1), false));                             \
    reinterpret_cast<MclPairing##class_name##G1*>(g1.get())                  \
        ->hash_to_pairing_curve_func_ =                                      \
        static_cast<void (*)(mcl::namespace_name::G1&, const std::string&)>( \
            mcl::namespace_name::hashAndMapToG1);                            \
                                                                             \
    auto g2 = std::unique_ptr<EcGroup>(new MclPairing##class_name##G2(       \
        meta, pairing_type, AnyPtr(p2), false));                             \
    reinterpret_cast<MclPairing##class_name##G2*>(g2.get())                  \
        ->hash_to_pairing_curve_func_ =                                      \
        static_cast<void (*)(mcl::namespace_name::G2&, const std::string&)>( \
            mcl::namespace_name::hashAndMapToG2);                            \
                                                                             \
    auto gt = std::unique_ptr<GroupTarget>(                                  \
        new MclPairing##class_name##GT(g1->GetOrder(), math::Type::Mul));    \
                                                                             \
    auto child_ptr =                                                         \
        std::make_unique<MclPairing##class_name>(meta, g1, g2, gt);          \
    child_ptr->pairing_func_ = mcl::namespace_name::pairing;                 \
    child_ptr->miller_func_ = mcl::namespace_name::millerLoop;               \
    child_ptr->final_exp_func_ = mcl::namespace_name::finalExp;              \
    return std::unique_ptr<PairingGroup>(std::move(child_ptr));              \
  }

#define CASE_DEFINE_BLS(mcl_pairing_macro, class_name, namespace_name)       \
  case MCL_##mcl_pairing_macro: {                                            \
    auto p1 = std::make_shared<MclPairing##class_name##G1::Ec>();            \
    auto p2 = std::make_shared<MclPairing##class_name##G2::Ec>();            \
    static bool once = [&] {                                                 \
      mcl::namespace_name::initPairing(mcl::mcl_pairing_macro);              \
      MclPairing##class_name##G1::BaseFp::setETHserialization(true);         \
      MclPairing##class_name##G1::Fr::setETHserialization(true);             \
      mcl::namespace_name::setMapToMode(MCL_MAP_TO_MODE_HASH_TO_CURVE);      \
      return true;                                                           \
    }();                                                                     \
    mcl::namespace_name::hashAndMapToG1(*p1, #class_name);                   \
    mcl::namespace_name::hashAndMapToG2(*p2, #class_name);                   \
    YACL_ENFORCE(once && !p1->isZero() && !p2->isZero());                    \
                                                                             \
    auto g1 = std::unique_ptr<EcGroup>(new MclPairing##class_name##G1(       \
        meta, pairing_type, AnyPtr(p1), false));                             \
    reinterpret_cast<MclPairing##class_name##G1*>(g1.get())                  \
        ->hash_to_pairing_curve_func_ =                                      \
        static_cast<void (*)(mcl::namespace_name::G1&, const std::string&)>( \
            mcl::namespace_name::hashAndMapToG1);                            \
                                                                             \
    auto g2 = std::unique_ptr<EcGroup>(new MclPairing##class_name##G2(       \
        meta, pairing_type, AnyPtr(p2), false));                             \
    reinterpret_cast<MclPairing##class_name##G2*>(g2.get())                  \
        ->hash_to_pairing_curve_func_ =                                      \
        static_cast<void (*)(mcl::namespace_name::G2&, const std::string&)>( \
            mcl::namespace_name::hashAndMapToG2);                            \
                                                                             \
    auto gt = std::unique_ptr<GroupTarget>(                                  \
        new MclPairing##class_name##GT(g1->GetOrder(), math::Type::Mul));    \
                                                                             \
    auto child_ptr =                                                         \
        std::make_unique<MclPairing##class_name>(meta, g1, g2, gt);          \
    child_ptr->pairing_func_ = mcl::namespace_name::pairing;                 \
    child_ptr->miller_func_ = mcl::namespace_name::millerLoop;               \
    child_ptr->final_exp_func_ = mcl::namespace_name::finalExp;              \
    return std::unique_ptr<PairingGroup>(std::move(child_ptr));              \
  }

// std::function<void(G2_&, const std::string&)>;
std::unique_ptr<PairingGroup> MclPGFactory::Create(const PairingMeta& meta) {
  auto pairing_type = Name2MclPairingEnum.at(meta.LowerName());
  switch (pairing_type) {
    // Note only BLS12_381 has impl standard(defined in IRTF) hash2G1 and
    // hash2G2
    case MCL_BLS12_381: {
      static auto p1 = std::make_shared<MclPairingBls12381G1::Ec>();
      static auto p2 = std::make_shared<MclPairingBls12381G2::Ec>();
      static bool once = [&] {
        mcl::bls12::initPairing(mcl::BLS12_381);
        mcl::bls12::G1::BaseFp::setETHserialization(true);
        MclPairingBls12381G1::Fr::setETHserialization(true);
        mcl::bls12::setMapToMode(MCL_MAP_TO_MODE_HASH_TO_CURVE);
        return true;
      }();
      mcl::bls12::hashAndMapToG1(*p1, "Bls12381");
      mcl::bls12::hashAndMapToG2(*p2, "Bls12381");
      YACL_ENFORCE(once && !p1->isZero() && !p2->isZero());

      // Init G1

      auto g1 = std::unique_ptr<EcGroup>(
          new MclPairingBls12381G1(meta, pairing_type, AnyPtr(p1), false));
      reinterpret_cast<MclPairingBls12381G1*>(g1.get())
          ->hash_to_pairing_curve_func_ =
          static_cast<void (*)(mcl::bls12::G1&, const std::string&)>(
              mcl::bls12::hashAndMapToG1);

      // Init G2
      auto g2 = std::unique_ptr<EcGroup>(
          new MclPairingBls12381G2(meta, pairing_type, AnyPtr(p2), false));
      reinterpret_cast<MclPairingBls12381G2*>(g2.get())
          ->hash_to_pairing_curve_func_ =
          static_cast<void (*)(mcl::bls12::G2&, const std::string&)>(
              mcl::bls12::hashAndMapToG2);

      // Init GT
      auto gt = std::unique_ptr<GroupTarget>(
          new MclPairingBls12381GT(g1->GetOrder(), math::Type::Mul));

      return std::unique_ptr<PairingGroup>(
          new MclPairingBls12381(meta, g1, g2, gt));
    }
      CASE_DEFINE(BN_SNARK1, BNSnark, bnsnark);
#ifdef MCL_ALL_PAIRING_FOR_YACL
      CASE_DEFINE(BN254, BN254, bn254);
      CASE_DEFINE(BN381_1, BN384M, bn382m);
      CASE_DEFINE(BN381_2, BN384R, bn382r);
      CASE_DEFINE(BN462, BN462, bn462);
      CASE_DEFINE(BN160, BN160, bn160);
      CASE_DEFINE(BLS12_377, Bls12377, bls123);
      CASE_DEFINE(BLS12_461, Bls12461, bls124);
      CASE_DEFINE(BN_P256, BN256, bn256);
#endif
    default:
      YACL_THROW("Not supported pairing {} in {}!", meta.LowerName(), kLibName);
  }
}

bool MclPGFactory::IsSupported(const PairingMeta& meta) {
  return Name2MclPairingEnum.count(meta.LowerName()) > 0;
}

REGISTER_PAIRING_LIBRARY(kLibName, 400, MclPGFactory::IsSupported,
                         MclPGFactory::Create);

}  // namespace yacl::crypto
