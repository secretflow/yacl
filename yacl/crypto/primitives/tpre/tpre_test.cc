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

TEST(TpreTest, Test1) {
  std::string iv = "123456789";
  TPRE tpre;
  Keys keys;

  /************************* Phase 1 *************************/
  // Start testing encryption and decryption functions
  std::unique_ptr<EcGroup> ecc_group = EcGroupFactory::Create("sm2");

  std::pair<Keys::PublicKey, Keys::PrivateKey> key_pair_A =
      keys.GenerateKeyPair(ecc_group);

  // test tpre.Encrypt
  std::string message = "hellooooooooooooo, I am 63, who are you?";

  std::pair<Capsule::CapsuleStruct, std::vector<uint8_t>> ct_1 =
      tpre.Encrypt(ecc_group, key_pair_A.first, iv, message);

  // test tpre.Decrypt

  std::string message_1 =
      tpre.Decrypt(ecc_group, ct_1.first, iv, ct_1.second, key_pair_A.second);

  // Determine if decryption was successful
  EXPECT_EQ(message, message_1);

  // End testing encryption and decryption functions

  /************************* Phase 2 *************************/
  // Start testing encryption, re-encryption, and decryption functions

  // Second test tpre.Encrypt
  std::string message_2 =
      "If you were a teardrop;In my eye, For fear of losing you, I would never "
      "cry. And if the golden sun, Should cease to shine its light, Just one "
      "smile from you, Would make my whole world bright.";

  std::pair<Capsule::CapsuleStruct, std::vector<uint8_t>> ct_2 =
      tpre.Encrypt(ecc_group, key_pair_A.first, iv, message_2);

  // test keys->GenerateReKey
  std::pair<Keys::PublicKey, Keys::PrivateKey> key_pair_B =
      keys.GenerateKeyPair(ecc_group);

  int N = 5;  // Number of all participants
  int t = 4;  // Threshold

  std::vector<Keys::KFrag> kfrags = keys.GenerateReKey(
      ecc_group, key_pair_A.second, key_pair_A.first, key_pair_B.first, N, t);

  // test tpre.ReEncrypt
  std::pair<std::vector<Capsule::CFrag>, std::vector<uint8_t>> re_ct_set;

  // You need to meet the number of participants to successfully decrypt,
  // otherwise decryption will not be successful

  for (int i = 0; i < t; i++) {
    std::pair<Capsule::CapsuleStruct, std::vector<uint8_t>> ct_2_i = {
        ct_2.first, ct_2.second};

    std::pair<Capsule::CFrag, std::vector<uint8_t>> re_ct_i =
        tpre.ReEncrypt(ecc_group, kfrags[i], ct_2_i);

    std::unique_ptr<Capsule::CFrag> cfrag_i_up(
        new Capsule::CFrag(re_ct_i.first));

    re_ct_set.first.push_back(re_ct_i.first);

    re_ct_set.second = re_ct_i.second;
  }

  // test tpre.DecryptFrags

  std::string message_3 =
      tpre.DecryptFrags(ecc_group, key_pair_B.second, key_pair_A.first,
                        key_pair_B.first, iv, re_ct_set);

  // Determine whether decryption was successful after performing re-encryption

  EXPECT_EQ(message_2, message_3);
}
}  // namespace yacl::crypto::test
