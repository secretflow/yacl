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

#include <map>

#include "yacl/crypto/ecc/libsodium/ed25519_group.h"

namespace yacl::crypto::sodium {

namespace {
const std::string kLibName = "libsodium";

std::map<CurveName, CurveParam> kPredefinedCurves = {
    {"ed25519",
     {
         (2_mp).Pow(255) - 19_mp,  // p = 2^255 - 19
         (2_mp).Pow(252) + "0x14def9dea2f79cd65812631a5cf5d3ed"_mp,  // n
         "8"_mp                                                      // h
     }}};

std::unique_ptr<EcGroup> Create(const CurveMeta &meta) {
  YACL_ENFORCE(kPredefinedCurves.count(meta.LowerName()) > 0,
               "curve {} not supported", meta.name);
  auto conf = kPredefinedCurves.at(meta.LowerName());

  if (meta.LowerName() == "ed25519") {
    return std::make_unique<Ed25519Group>(meta, conf);
  } else {
    YACL_THROW("unexpected curve {}", meta.name);
  }
}

bool IsSupported(const CurveMeta &meta) {
  return kPredefinedCurves.count(meta.LowerName()) > 0;
}

REGISTER_EC_LIBRARY(kLibName, 800, IsSupported, Create);

}  // namespace

std::string SodiumGroup::GetLibraryName() const { return kLibName; }

}  // namespace yacl::crypto::sodium
