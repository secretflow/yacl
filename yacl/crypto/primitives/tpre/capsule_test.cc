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

class CapsuleTest : public testing::Test {};

TEST_F(CapsuleTest, Test1) {
  std::unique_ptr<EcGroup> ecc_group = EcGroupFactory::Create("sm2");
  Keys keys;

  std::pair<std::unique_ptr<Keys::PublicKey>, std::unique_ptr<Keys::PrivateKey>>
      key_pair_alice = keys.GenerateKeyPair(std::move(ecc_group));

  ecc_group = EcGroupFactory::Create("sm2");
  std::pair<std::unique_ptr<Keys::PublicKey>, std::unique_ptr<Keys::PrivateKey>>
      key_pair_bob = keys.GenerateKeyPair(std::move(ecc_group));

  ecc_group = EcGroupFactory::Create("sm2");
  std::unique_ptr<Keys::PublicKey> public_key_alice_dup(
      new Keys::PublicKey{key_pair_alice.first->g, key_pair_alice.first->y});
  std::unique_ptr<Keys::PrivateKey> private_key_alice_dup(
      new Keys::PrivateKey{key_pair_alice.second->x});

  std::unique_ptr<Keys::PublicKey> public_key_alice_dup_dup(
      new Keys::PublicKey{key_pair_alice.first->g, key_pair_alice.first->y});
  std::unique_ptr<Keys::PrivateKey> private_key_alice_dup_dup(
      new Keys::PrivateKey{key_pair_alice.second->x});

  std::unique_ptr<Keys::PublicKey> public_key_bob_dup(
      new Keys::PublicKey{key_pair_bob.first->g, key_pair_bob.first->y});
  std::unique_ptr<Keys::PrivateKey> private_key_bob_dup(
      new Keys::PrivateKey{key_pair_bob.second->x});

  Capsule cs;
  std::pair<std::unique_ptr<Capsule::CapsuleStruct>, std::vector<uint8_t>>
      capsule_pair =
          cs.EnCapsulate(std::move(ecc_group), std::move(key_pair_alice.first));

  std::string dek_str = absl::BytesToHexString(absl::string_view(
      (const char*)capsule_pair.second.data(), capsule_pair.second.size()));
  //   std::cout << "DEK = " << dek_str << std::endl;

  ecc_group = EcGroupFactory::Create("sm2");
  std::vector<Keys::KFrag> kfrags = keys.GenerateReKey(
      std::move(ecc_group), std::move(private_key_alice_dup),
      std::move(public_key_alice_dup), std::move(public_key_bob_dup), 5, 4);

  ecc_group = EcGroupFactory::Create("sm2");
  std::vector<std::unique_ptr<Capsule::CFrag>> cfrags;
  auto capsule_pair_first = capsule_pair.first.get();
  for (int i = 0; i < 4; i++) {
    Capsule::CapsuleStruct* capsule_struct_i = new Capsule::CapsuleStruct{
        capsule_pair_first->E, capsule_pair_first->V, capsule_pair_first->s};
    std::unique_ptr<Capsule::CapsuleStruct> capsule_struct_i_up(
        capsule_struct_i);
    Keys::KFrag* kfrag_i = new Keys::KFrag{
        kfrags[i].id,  kfrags[i].rk,  kfrags[i].X_A, kfrags[i].U,
        kfrags[i].U_1, kfrags[i].z_1, kfrags[i].z_2};

    std::unique_ptr<Keys::KFrag> kfrag_up(kfrag_i);

    std::unique_ptr<Capsule::CFrag> cfrag_i =
        cs.ReEncapsulate(std::move(ecc_group), std::move(kfrag_up),
                         std::move(capsule_struct_i_up));

    cfrags.push_back(std::move(cfrag_i));
    ecc_group = EcGroupFactory::Create("sm2");
  }

  ecc_group = EcGroupFactory::Create("sm2");
  auto dek =
      cs.DeCapsulateFrags(std::move(ecc_group), std::move(key_pair_bob.second),
                          std::move(public_key_alice_dup_dup),
                          std::move(key_pair_bob.first), std::move(cfrags));

  std::string dek_str1 = absl::BytesToHexString(
      absl::string_view((const char*)dek.data(), dek.size()));

  EXPECT_EQ(dek_str, dek_str1);
}
}  // namespace yacl::crypto::test
