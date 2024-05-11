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

#include "yacl/crypto/ecc/mcl/mcl_ec_group.h"

namespace yacl::crypto {

std::map<CurveName, int> Name2MclCurveEnum = {
    {"secp192k1", MCL_SECP192K1},
    {"secp224k1", MCL_SECP224K1},
    {"secp256k1", MCL_SECP256K1},
    // Same as NIST_P384, more info see yacl/crypto/ecc/curve_meta.cc
    {"secp384r1", MCL_SECP384R1},
    {"secp192r1", MCL_NIST_P192},
    {"secp224r1", MCL_NIST_P224},
    {"secp256r1", MCL_NIST_P256},
    {"secp160k1", MCL_SECP160K1},
};

#define CASE_DEFINE(mcl_curve_macro, class_name)                         \
  case mcl_curve_macro: {                                                \
    static auto generator = [&] {                                        \
      auto p = std::make_shared<class_name::Ec>();                       \
      mcl::initCurve<class_name::Ec, class_name::Fr>(                    \
          curve_type, p.get(), mcl::fp::Mode::FP_AUTO, mcl::ec::Jacobi); \
      return p;                                                          \
    }();                                                                 \
    YACL_ENFORCE(!generator->isZero());                                  \
    return std::unique_ptr<EcGroup>(                                     \
        new class_name(meta, curve_type, AnyPtr(generator)));            \
  }

std::unique_ptr<EcGroup> MclEGFactory::Create(const CurveMeta& meta) {
  YACL_ENFORCE(Name2MclCurveEnum.count(meta.LowerName()) > 0,
               "curve {} not supported by mcl", meta.name);
  auto curve_type = Name2MclCurveEnum.at(meta.LowerName());
  switch (curve_type) {
    CASE_DEFINE(MCL_SECP160K1, MclSecp160k1)
    CASE_DEFINE(MCL_SECP192K1, MclSecp192k1)
    CASE_DEFINE(MCL_SECP224K1, MclSecp224k1)
    CASE_DEFINE(MCL_SECP256K1, MclSecp256k1)
    CASE_DEFINE(MCL_SECP384R1, MclSecp384r1)
    CASE_DEFINE(MCL_NIST_P192, MclNistP192)
    CASE_DEFINE(MCL_NIST_P224, MclNistP224)
    CASE_DEFINE(MCL_NIST_P256, MclNistP256)
    default:
      YACL_THROW("Not supported curve in {}!", kLibName);
  }
}

bool MclEGFactory::IsSupported(const CurveMeta& meta) {
  return Name2MclCurveEnum.count(meta.LowerName()) > 0;
}

REGISTER_EC_LIBRARY(kLibName, 400, MclEGFactory::IsSupported,
                    MclEGFactory::Create);

}  // namespace yacl::crypto
