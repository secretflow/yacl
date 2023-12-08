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

#include "yacl/math/mpint/mp_int.h"
#include "yacl/utils/spi/argument/argument.h"

// How to use mpint field?
//
// > #include "yacl/math/galois_field/gf_spi.h"
// > #include "yacl/math/galois_field/mpint_field/configs.h"
// >
// > void foo() {
// >  auto gf = GaloisFieldFactory::Instance().Create("Zn", ArgMod = 13_mp);
// >  auto sum = gf->Add(10_mp, 5_mp);  // output 2
// > }
//
// Note 1: Do not include 'mpint_field.h', include 'configs.h' instead.
// Note 2: Get mpint field instance by `GaloisFieldFactory::Instance().Create()`

namespace yacl::math::mpf {

inline const std::string kFieldName = "Zp";
inline const std::string kLibName = "mpint";

// Prd-defined options...
DECLARE_ARG(MPInt, Mod);

}  // namespace yacl::math::mpf
