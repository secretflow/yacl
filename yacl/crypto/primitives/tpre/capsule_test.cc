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

#include "yacl/crypto/primitives/tpre/capsule.h"

#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "gtest/gtest.h"

#include "yacl/crypto/primitives/tpre/keys.h"

namespace yacl::crypto::test {

TEST(CapsuleTest, Test1) {
  std::unique_ptr<EcGroup> ecc_group = EcGroupFactory::Create("sm2");
  Keys keys;

  std::pair<Keys::PublicKey, Keys::PrivateKey> key_pair_alice =
      keys.GenerateKeyPair(ecc_group);

  std::pair<Keys::PublicKey, Keys::PrivateKey> key_pair_bob =
      keys.GenerateKeyPair(ecc_group);

  Capsule cs;
  std::pair<Capsule::CapsuleStruct, std::vector<uint8_t>> capsule_pair =
      cs.EnCapsulate(ecc_group, key_pair_alice.first);

  std::string dek_str = absl::BytesToHexString(absl::string_view(
      (const char*)capsule_pair.second.data(), capsule_pair.second.size()));

  std::vector<Keys::KFrag> kfrags =
      keys.GenerateReKey(ecc_group, key_pair_alice.second, key_pair_alice.first,
                         key_pair_bob.first, 5, 4);

  std::vector<Capsule::CFrag> cfrags;
  for (int i = 0; i < 4; i++) {
    Capsule::CFrag cfrag_i =
        cs.ReEncapsulate(ecc_group, kfrags[i], capsule_pair.first);
    cfrags.push_back(cfrag_i);
  }

  auto dek =
      cs.DeCapsulateFrags(ecc_group, key_pair_bob.second, key_pair_alice.first,
                          key_pair_bob.first, cfrags);

  std::string dek_str1 = absl::BytesToHexString(
      absl::string_view((const char*)dek.data(), dek.size()));

  EXPECT_EQ(dek_str, dek_str1);
}
}  // namespace yacl::crypto::test
