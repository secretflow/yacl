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

#include "gtest/gtest.h"

#include "yacl/base/exception.h"
#include "yacl/math/mpint/mp_int.h"

namespace yacl::crypto::test {

TEST(HashTest, Test1) {
  std::unique_ptr<EcGroup> ecc_group = EcGroupFactory::Instance().Create("sm2");

  auto hash_value = CipherHash("tpre", ecc_group);
  EXPECT_TRUE(hash_value > 0_mp);
  EXPECT_EQ(hash_value.ToHexString(),
            "3532674C20DA7E34FE48093538D7E4167E3C39472B19EBACE593579EA6073329");

  auto hash_value2 = CipherHash({ecc_group->GetGenerator()}, ecc_group);
  EXPECT_EQ(hash_value2.ToHexString(),
            "2FE6D05F44F7387077FE1ACECC457BBE3D208C513CAA94FDBA3B58C691D84F21");

  auto hash_value3 = CipherHash(
      {ecc_group->GetGenerator(), ecc_group->MulBase(2_mp)}, ecc_group);
  EXPECT_EQ(hash_value3.ToHexString(),
            "2A37F6D7231C9CC72D8B8FBEF9A859992B9BDADAC1BDB9E73D881967EB145854");
}

}  // namespace yacl::crypto::test
