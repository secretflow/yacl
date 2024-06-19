// Copyright 2023 Chengfang Financial Technology Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <string>

#include "yacl/crypto/ecc/ecc_spi.h"

namespace yacl::crypto {

// @brief Cryptographic hash function, h_x = 1 + Bignum(sm3(x)||sm3(sm3(x))),
//        where n is the degree of EC Group, and x is input mod n-1
// @param input
// @param curve_id, elliptic curve type
// @return hash value
MPInt CipherHash(ByteContainerView input,
                 const std::unique_ptr<EcGroup>& ecc_group);

MPInt CipherHash(std::initializer_list<EcPoint> input,
                 const std::unique_ptr<EcGroup>& ecc_group);

}  // namespace yacl::crypto
