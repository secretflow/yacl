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

#include "yacl/crypto/primitives/tpre/tpre.h"

#include "absl/strings/escaping.h"
#include "gtest/gtest.h"

namespace yacl::crypto::test {

class TpreTest : public testing::Test {};

TEST_F(TpreTest, Test1) {
  std::string iv = "123456789";
  TPRE tpre;
  Keys keys;

  /************************* Phase 1 *************************/
  // Start testing encryption and decryption functions
  std::unique_ptr<EcGroup> ecc_group = EcGroupFactory::Create("sm2");

  std::pair<std::unique_ptr<Keys::PublicKey>, std::unique_ptr<Keys::PrivateKey>>
      key_pair_A = keys.GenerateKeyPair(std::move(ecc_group));

  Keys::PublicKey* pk_A = key_pair_A.first.get();
  Keys::PrivateKey* sk_A = key_pair_A.second.get();

  ecc_group = EcGroupFactory::Create("sm2");
  std::unique_ptr<Keys::PublicKey> pk_A_0(
      new Keys::PublicKey{pk_A->g, pk_A->y});

  // test tpre.Encrypt
  std::string message = "hellooooooooooooo, I'am 63, who are you?";

  ecc_group = EcGroupFactory::Create("sm2");
  std::pair<std::unique_ptr<Capsule::CapsuleStruct>, std::vector<uint8_t>>
      ct_1 = tpre.Encrypt(std::move(ecc_group), std::move(pk_A_0), iv, message);

  // test tpre.Decrypt
  std::unique_ptr<Keys::PrivateKey> sk_A_1(new Keys::PrivateKey{sk_A->x});

  ecc_group = EcGroupFactory::Create("sm2");
  std::string message_1 =
      tpre.Decrypt(std::move(ecc_group), std::move(ct_1.first), iv, ct_1.second,
                   std::move(sk_A_1));

  // Determine if decryption was successful
  EXPECT_EQ(message, message_1);

  // End testing encryption and decryption functions

  /************************* Phase 2 *************************/
  // Start testing encryption, re encryption, and decryption functions

  // Second test tpre.Encrypt
  std::string message_2 =
      "If you were a teardrop;In my eye, For fear of losing you, I would never "
      "cry. And if the golden sun, Should cease to shine its light, Just one "
      "smile from you, Would make my whole world bright.";

  ecc_group = EcGroupFactory::Create("sm2");
  std::unique_ptr<Keys::PublicKey> pk_A_1(
      new Keys::PublicKey{pk_A->g, pk_A->y});
  std::pair<std::unique_ptr<Capsule::CapsuleStruct>, std::vector<uint8_t>>
      ct_2 =
          tpre.Encrypt(std::move(ecc_group), std::move(pk_A_1), iv, message_2);

  ecc_group = EcGroupFactory::Create("sm2");
  // test keys->GenerateReKey
  std::unique_ptr<Keys::PrivateKey> sk_A_2(new Keys::PrivateKey{sk_A->x});
  std::unique_ptr<Keys::PublicKey> pk_A_2(
      new Keys::PublicKey{pk_A->g, pk_A->y});

  std::pair<std::unique_ptr<Keys::PublicKey>, std::unique_ptr<Keys::PrivateKey>>
      key_pair_B = keys.GenerateKeyPair(std::move(ecc_group));

  ecc_group = EcGroupFactory::Create("sm2");
  Keys::PrivateKey* sk_B = key_pair_B.second.get();
  Keys::PublicKey* pk_B = key_pair_B.first.get();

  std::unique_ptr<Keys::PublicKey> pk_B_1(
      new Keys::PublicKey{pk_B->g, pk_B->y});

  int N = 5;  // Number of all participants
  int t = 4;  // Threshold

  std::vector<Keys::KFrag> kfrags =
      keys.GenerateReKey(std::move(ecc_group), std::move(sk_A_2),
                         std::move(pk_A_2), std::move(pk_B_1), N, t);

  // test tpre.ReEncrypt
  std::pair<std::vector<std::unique_ptr<Capsule::CFrag>>, std::vector<uint8_t>>
      re_ct_set;

  ecc_group = EcGroupFactory::Create("sm2");

  // You need to meet the number of participants to successfully decrypt,
  // otherwise decryption will not be successful
  for (int i = 0; i < t; i++) {
    Capsule::CapsuleStruct* capsule_struct_i =
        new Capsule::CapsuleStruct{ct_2.first->E, ct_2.first->V, ct_2.first->s};

    std::unique_ptr<Capsule::CapsuleStruct> capsule_struct_i_up(
        capsule_struct_i);
    std::pair<std::unique_ptr<Capsule::CapsuleStruct>, std::vector<uint8_t>>
        ct_2_i = {std::move(capsule_struct_i_up), ct_2.second};

    Keys::KFrag* kfrag_i = new Keys::KFrag{
        kfrags[i].id,  kfrags[i].rk,  kfrags[i].X_A, kfrags[i].U,
        kfrags[i].U_1, kfrags[i].z_1, kfrags[i].z_2};

    std::unique_ptr<Keys::KFrag> kfrag_up(kfrag_i);

    ecc_group = EcGroupFactory::Create("sm2");
    std::pair<std::unique_ptr<Capsule::CFrag>, std::vector<uint8_t>> re_ct_i =
        tpre.ReEncrypt(std::move(ecc_group), std::move(kfrag_up),
                       std::move(ct_2_i));

    re_ct_set.first.push_back(std::move(re_ct_i.first));
    re_ct_set.second = re_ct_i.second;

    ecc_group = EcGroupFactory::Create("sm2");
  }

  // test tpre.DecryptFrags
  std::unique_ptr<Keys::PrivateKey> sk_B_1(new Keys::PrivateKey{sk_B->x});
  std::unique_ptr<Keys::PublicKey> pk_A_3(
      new Keys::PublicKey{pk_A->g, pk_A->y});

  std::unique_ptr<Keys::PublicKey> pk_B_2(
      new Keys::PublicKey{pk_B->g, pk_B->y});

  ecc_group = EcGroupFactory::Create("sm2");
  std::string message_3 = tpre.DecryptFrags(
      std::move(ecc_group), std::move(sk_B_1), std::move(pk_A_3),
      std::move(pk_B_2), iv, std::move(re_ct_set));

  // Determine whether decryption was successful after performing re-encryption
  EXPECT_EQ(message_2, message_3);
}
}  // namespace yacl::crypto::test
