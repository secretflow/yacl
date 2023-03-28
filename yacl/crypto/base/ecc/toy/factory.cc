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

#include <memory>

#include "yacl/crypto/base/ecc/toy/montgomery.h"
#include "yacl/crypto/base/ecc/toy/weierstrass.h"

namespace yacl::crypto::toy {

static std::map<CurveName, CurveParam> kPredefinedCurves = {
    {"secp256k1",
     {
         "0x0"_mp,  // A
         "0x7"_mp,  // B
         {"0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"_mp,
          "0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"_mp},
         "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"_mp,
         "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"_mp,
         "0x1"_mp  // h
     }},
    // https://www.oscca.gov.cn/sca/xxgk/2010-12/17/content_1002386.shtml
    {"sm2",
     {
         "0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"_mp,
         "0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"_mp,
         {"0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"_mp,
          "0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"_mp},
         "0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"_mp,
         "0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"_mp,
         "0x1"_mp  // h
     }},
    {"curve25519",
     {
         "486662"_mp,  // A
         "1"_mp,       // B
         {"9"_mp,
          "0x20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9"_mp},
         (2_mp).Pow(255) - 19_mp,  // p = 2^255 - 19
         (2_mp).Pow(252) + "0x14def9dea2f79cd65812631a5cf5d3ed"_mp,  // n
         "8"_mp                                                      // h
     }}};

std::unique_ptr<EcGroup> Create(const CurveMeta &meta) {
  YACL_ENFORCE(kPredefinedCurves.count(meta.LowerName()) > 0,
               "curve {} not supported", meta.name);
  auto conf = kPredefinedCurves.at(meta.LowerName());
  if (meta.form == CurveForm::Montgomery) {
    return std::make_unique<ToyXGroup>(meta, conf);
  } else {
    return std::make_unique<ToyWeierstrassGroup>(meta, conf);
  }
}

bool IsSupported(const CurveMeta &meta) {
  return kPredefinedCurves.count(meta.LowerName()) > 0;
}

REGISTER_EC_LIBRARY(kLibName, 10, IsSupported, Create);

}  // namespace yacl::crypto::toy
