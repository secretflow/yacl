// Copyright 2025 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <gtest/gtest.h>
#include <spdlog/spdlog.h>

#include <vector>

#include "hesm2/ahesm2.h"
#include "hesm2/ciphertext.h"
#include "hesm2/config.h"
#include "hesm2/public_key.h"

#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/utils/spi/spi_factory.h"

using namespace examples::hesm2;
using namespace yacl::crypto;
using namespace yacl::math;

TEST(SerializationTest, PublicKey) {
  SPDLOG_INFO("Testing PublicKey Serialization...");
  std::shared_ptr<EcGroup> ec_group = EcGroupFactory::Instance().Create("sm2");
  ASSERT_NE(ec_group, nullptr);
  MPInt sk_val;
  MPInt::RandomLtN(ec_group->GetOrder(), &sk_val);
  auto pk_point = ec_group->MulBase(sk_val);
  PublicKey pk(pk_point, ec_group);

  yacl::Buffer buf = pk.Serialize();
  PublicKey pk_des = PublicKey::Deserialize(buf, ec_group);
  EXPECT_TRUE(ec_group->PointEqual(pk.GetPoint(), pk_des.GetPoint()));
}

TEST(SerializationTest, Ciphertext) {
  SPDLOG_INFO("Testing Ciphertext Serialization...");
  std::shared_ptr<EcGroup> ec_group = EcGroupFactory::Instance().Create("sm2");
  ASSERT_NE(ec_group, nullptr);
  MPInt sk_val;
  MPInt::RandomLtN(ec_group->GetOrder(), &sk_val);
  auto pk_point = ec_group->MulBase(sk_val);
  PublicKey pk(pk_point, ec_group);

  auto c0 = Encrypt(yacl::math::MPInt(0), pk);
  yacl::Buffer buf = SerializeCiphertext(c0, pk);
  Ciphertext ct_des = DeserializeCiphertext(buf, pk);
  EXPECT_TRUE(ec_group->PointEqual(c0.GetC1(), ct_des.GetC1()));
  EXPECT_TRUE(ec_group->PointEqual(c0.GetC2(), ct_des.GetC2()));
}

TEST(SerializationTest, CiphertextVector) {
  SPDLOG_INFO("Testing Ciphertext Vector Serialization...");
  std::shared_ptr<EcGroup> ec_group = EcGroupFactory::Instance().Create("sm2");
  ASSERT_NE(ec_group, nullptr);
  MPInt sk_val;
  MPInt::RandomLtN(ec_group->GetOrder(), &sk_val);
  auto pk_point = ec_group->MulBase(sk_val);
  PublicKey pk(pk_point, ec_group);

  std::vector<Ciphertext> cts;
  for (int i = 0; i < 5; ++i) {
    MPInt m(i + 100);
    cts.push_back(Encrypt(m, pk));
  }

  yacl::Buffer buf = SerializeCiphertexts(cts, pk);
  std::vector<Ciphertext> cts_des = DeserializeCiphertexts(buf, pk);

  ASSERT_EQ(cts_des.size(), cts.size());
  for (size_t i = 0; i < cts_des.size(); ++i) {
    EXPECT_TRUE(ec_group->PointEqual(cts[i].GetC1(), cts_des[i].GetC1()));
    EXPECT_TRUE(ec_group->PointEqual(cts[i].GetC2(), cts_des[i].GetC2()));
  }
}
