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

#include "yacl/crypto/tpre/hash.h"

#include <stdio.h>
#include <stdlib.h>

#include <bitset>
#include <string>
#include <vector>

#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/crypto/tpre/kdf.h"

namespace yacl::crypto {
// h_x = 1 + Bignum(sm3(x)||sm3(sm3(x))) mod n-1
// where n is the degree of EC Group, and x is input
MPInt CipherHash(ByteContainerView input,
                 const std::unique_ptr<EcGroup>& ecc_group) {
  auto hash_value_0 = Sm3(input);
  auto hash_value_1 = Sm3(hash_value_0);

  std::vector<uint8_t> buf;
  buf.insert(buf.end(), hash_value_0.begin(), hash_value_0.end());
  buf.insert(buf.end(), hash_value_1.begin(), hash_value_1.end());

  MPInt hash_bn;
  hash_bn.FromMagBytes(buf);

  // h_x = 1 + Bignum(sm3(x)||sm3(sm3(x))) mod n-1
  MPInt h_x = hash_bn.AddMod(1_mp, ecc_group->GetOrder() - 1_mp);

  return h_x;
}

MPInt CipherHash(std::initializer_list<EcPoint> inputs,
                 const std::unique_ptr<EcGroup>& ecc_group) {
  auto len = ecc_group->GetSerializeLength();
  Buffer buf(len * inputs.size());

  uint8_t index = 0;
  for (const auto& p : inputs) {
    ecc_group->SerializePoint(p, buf.data<uint8_t>() + index * len, len);
    index++;
  }

  return CipherHash(buf, ecc_group);
}

}  // namespace yacl::crypto
