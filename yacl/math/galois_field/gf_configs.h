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

namespace yacl::math {

//==   Field names   ==//

inline const std::string kPrimeField = "GF_p";
inline const std::string kExtensionField = "GF_p^k";
inline const std::string kBinaryField = "GF_2^k";

//==   Field options...   ==//

// configs for kPrimeField, kExtensionField
DECLARE_ARG(MPInt, Mod);  // the value of p in GF_p

// configs for kExtensionField, kBinaryField
DECLARE_ARG(uint64_t, Degree);

// configs for max bit size for underlying prime number
DECLARE_ARG(uint64_t, MaxBitSize);

//==   Supported lib list...   ==//

// Example:
// How to use mpint field?
//
// > #include "yacl/math/galois_field/gf_spi.h"
// >
// > void foo() {
// >  auto gf = GaloisFieldFactory::Instance().Create("Zn", ArgMod = 13_mp);
// >  auto sum = gf->Add(10_mp, 5_mp);  // output 2
// > }
//
// Note 1: Do not include any field in mpint_field dir.
// Note 2: Get mpint field instance by `GaloisFieldFactory::Instance().Create()`

inline const std::string kMPIntLib = "mpint";
inline const std::string kMclLib = "libmcl";

}  // namespace yacl::math
