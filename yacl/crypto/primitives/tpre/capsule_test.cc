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
  std::unique_ptr<Keys::PublicKey> pk_A(
      new Keys::PublicKey(key_pair_alice.first));
  std::unique_ptr<Keys::PrivateKey> sk_A(
      new Keys::PrivateKey(key_pair_alice.second));

  std::pair<Keys::PublicKey, Keys::PrivateKey> key_pair_bob =
      keys.GenerateKeyPair(ecc_group);
  std::unique_ptr<Keys::PublicKey> pk_B(
      new Keys::PublicKey(key_pair_bob.first));
  std::unique_ptr<Keys::PrivateKey> sk_B(
      new Keys::PrivateKey(key_pair_bob.second));

  Capsule cs;
  std::pair<Capsule::CapsuleStruct, std::vector<uint8_t>> capsule_pair =
      cs.EnCapsulate(ecc_group, pk_A);

  std::string dek_str = absl::BytesToHexString(absl::string_view(
      (const char*)capsule_pair.second.data(), capsule_pair.second.size()));

  std::vector<Keys::KFrag> kfrags =
      keys.GenerateReKey(ecc_group, sk_A, pk_A, pk_B, 5, 4);

  std::vector<std::unique_ptr<Capsule::CFrag>> cfrags;
  auto capsule_pair_first = capsule_pair.first;
  for (int i = 0; i < 4; i++) {
    Capsule::CapsuleStruct* capsule_struct_i = new Capsule::CapsuleStruct{
        capsule_pair_first.E, capsule_pair_first.V, capsule_pair_first.s};
    std::unique_ptr<Capsule::CapsuleStruct> capsule_struct_i_up(
        capsule_struct_i);
    Keys::KFrag* kfrag_i = new Keys::KFrag{
        kfrags[i].id,  kfrags[i].rk,  kfrags[i].X_A, kfrags[i].U,
        kfrags[i].U_1, kfrags[i].z_1, kfrags[i].z_2};

    std::unique_ptr<Keys::KFrag> kfrag_up(kfrag_i);

    Capsule::CFrag cfrag_i =
        cs.ReEncapsulate(ecc_group, kfrag_up, capsule_struct_i_up);
    std::unique_ptr<Capsule::CFrag> cfrag_i_up(new Capsule::CFrag(cfrag_i));
    cfrags.push_back(std::move(cfrag_i_up));
  }

  auto dek = cs.DeCapsulateFrags(ecc_group, sk_B, pk_A, pk_B, cfrags);

  std::string dek_str1 = absl::BytesToHexString(
      absl::string_view((const char*)dek.data(), dek.size()));

  EXPECT_EQ(dek_str, dek_str1);
}
}  // namespace yacl::crypto::test
