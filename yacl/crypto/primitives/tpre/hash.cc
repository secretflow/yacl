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

#include "yacl/crypto/primitives/tpre/hash.h"

#include <stdio.h>
#include <stdlib.h>

#include <bitset>
#include <string>
#include <vector>

#include "yacl/base/dynamic_bitset.h"
#include "yacl/crypto/base/hash/hash_utils.h"
#include "yacl/crypto/primitives/tpre/kdf.h"

namespace yacl::crypto {
// h_x = 1 + Bignum(sm3(x)||sm3(sm3(x))) mod n-1
// where n is the degree of EC Group, and x is input
MPInt CipherHash(ByteContainerView input,
                 const std::unique_ptr<EcGroup>& ecc_group) {
  std::array<unsigned char, 32> hash_value_0 = Sm3(input);
  std::array<unsigned char, 32> hash_value_1 = Sm3(hash_value_0);

  dynamic_bitset<uint8_t> binary;
  binary.append(hash_value_0.begin(), hash_value_0.end());
  binary.append(hash_value_1.begin(), hash_value_1.end());
  MPInt hash_bn(binary.to_string(), 2);

  MPInt one_bn(1);
  // h_x = 1 + Bignum(sm3(x)||sm3(sm3(x))) mod n-1
  MPInt h_x = one_bn.AddMod(hash_bn, ecc_group->GetOrder() - one_bn);

  return h_x;
}
}  // namespace yacl::crypto
