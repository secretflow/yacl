// Copyright 2024 Ant Group Co., Ltd.
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

#include "yacl/crypto/ecc/FourQlib/FourQ_group.h"

namespace yacl::crypto::FourQ {

namespace {

const std::string kLibName = "FourQlib";

std::unique_ptr<EcGroup> Create(const CurveMeta &meta) {
  YACL_ENFORCE(meta.LowerName() == "fourq", "curve {} not supported",
               meta.name);
  return std::make_unique<FourQGroup>(meta);
}

bool IsSupported(const CurveMeta &meta) { return meta.LowerName() == "fourq"; }

REGISTER_EC_LIBRARY(kLibName, 1500, IsSupported, Create);

}  // namespace

std::string FourQGroup::GetLibraryName() const { return kLibName; }

}  // namespace yacl::crypto::FourQ
