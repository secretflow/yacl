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

#include "yacl/crypto/primitives/tpre/keys.h"

#include <vector>

#include "gtest/gtest.h"

#include "yacl/base/exception.h"
#include "yacl/crypto/base/mpint/mp_int.h"

namespace yacl::crypto::test {

TEST(KeyTest, Test1) {
  MPInt zero(0);
  std::unique_ptr<EcGroup> ecc_group = EcGroupFactory::Create("sm2");

  Keys keys;
  std::pair<Keys::PublicKey, Keys::PrivateKey> key_pair_alice =
      keys.GenerateKeyPair(ecc_group);

  // According to the official SM2 document
  // The hexadecimal of generator is:
  // Gx = 32C4AE2C 1F198119 5F990446 6A39C994 8FE30BBF F2660BE1 715A4589
  // 334C74C7
  // Gy = BC3736A2 F4F6779C 59BDCEE3 6B692153 D0A9877C C62A4740 02DF32E5
  // 2139F0A0

  // When converting it to decimal, we have :
  // "(2296314654723705055947953136255007457880
  // 2567295341616970375194840604139615431,
  // "85132369209828568825618990617112496413088
  // 388631904505083283536607588877201568)";

  std::string generator_str =
      "(2296314654723705055947953136255007457880256729534161697037519"
      "4840604139"
      "615431, "
      "85132369209828568825618990617112496413088388631904505083283536"
      "6075888772"
      "01568)";
  EXPECT_EQ(ecc_group->GetAffinePoint(key_pair_alice.first.g).ToString(),
            generator_str);

  std::pair<Keys::PublicKey, Keys::PrivateKey> key_pair_bob =
      keys.GenerateKeyPair(ecc_group);

  std::vector<Keys::KFrag> kfrags =
      keys.GenerateReKey(ecc_group, key_pair_alice.second, key_pair_alice.first,
                         key_pair_bob.first, 5, 4);

  for (int i = 0; i < 5; i++) {
    EXPECT_TRUE(kfrags[i].id > zero);
  }
}
}  // namespace yacl::crypto::test
