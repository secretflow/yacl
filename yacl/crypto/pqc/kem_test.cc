// Copyright 2025 Ant Group Co., Ltd.
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

#include "yacl/crypto/pqc/kem.h"

#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "spdlog/spdlog.h"

namespace yacl::crypto {

void test_kem(const std::string& kem_name) {
  Kem kem(kem_name);
  // Test key pair generation
  auto [pk, sk] = kem.GenKeyPair();
  EXPECT_EQ(pk.size(), kem.GetPublicKeySize());
  EXPECT_EQ(sk.size(), kem.GetSecretKeySize());

  // Test encapsulation and decapsulation
  auto [ciphertext, shared_secret1] = kem.Encapsulate(pk);
  EXPECT_EQ(ciphertext.size(), kem.GetCiphertextSize());
  EXPECT_EQ(shared_secret1.size(), kem.GetSharedSecretSize());

  auto shared_secret2 = kem.Decapsulate(sk, ciphertext);
  EXPECT_EQ(shared_secret2.size(), kem.GetSharedSecretSize());

  EXPECT_EQ(shared_secret1, shared_secret2) << "Shared secrets do not match!";
}

TEST(KemTest, BasicFunctionality) {
  std::vector<std::string> enabled_kems = Kem::GetEnabledKem();
  for (const auto& kem_name : enabled_kems) {
    test_kem(kem_name);
  }
}

TEST(KemTest, AlgorithmInfo) {
  auto supported_kems = Kem::GetSupportedKem();
  EXPECT_EQ(supported_kems.size(), Kem::GetKemAlgCount());

  // Test specific algorithm properties
  std::string kem_name = "ML-KEM-512";
  Kem kem(kem_name);

  EXPECT_FALSE(kem.GetKemAlgVersion().empty());
  EXPECT_GT(kem.GetClaimedNistLevel(), 0);
  EXPECT_TRUE(kem.IsIndCca());
}

}  // namespace yacl::crypto
