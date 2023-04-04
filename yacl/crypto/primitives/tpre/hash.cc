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

#include "yacl/crypto/base/hash/hash_utils.h"
#include "yacl/crypto/primitives/tpre/kdf.h"

namespace yacl::crypto {
// h_x = 1 + Bignum(sm3(x)||sm3(sm3(x))) mod n-1
// where n is the degree of EC Group, and x is input
MPInt CipherHash(absl::string_view input, std::string curve_type) {
  std::array<unsigned char, 32> hash_value_0 = Sm3(input);
  absl::string_view hash_value_0_view(
      reinterpret_cast<const char*>(hash_value_0.data()), hash_value_0.size());
  std::array<unsigned char, 32> hash_value_1 = Sm3(hash_value_0_view);

  absl::string_view hash_value_1_view(
      reinterpret_cast<const char*>(hash_value_1.data()), hash_value_1.size());

  std::string hash_value_0_view_join_hash_value_1_view =
      std::string(hash_value_0_view) + std::string(hash_value_1_view);
  MPInt one_bn(1);

  // Convert an unreadable string to a binary representation
  std::string binary_str;
  for (auto& i : hash_value_0_view_join_hash_value_1_view) {
    std::bitset<8> bits(i);
    binary_str += bits.to_string();
  }
  MPInt hash_value_0_view_join_hash_value_1_view_bn(binary_str);

  auto ecc_group = EcGroupFactory::Create(curve_type);

  // h_x = 1 + Bignum(sm3(x)||sm3(sm3(x))) mod n-1
  MPInt h_x = one_bn.AddMod(hash_value_0_view_join_hash_value_1_view_bn,
                            ecc_group->GetOrder() - one_bn);

  return h_x;
}
}  // namespace yacl::crypto
