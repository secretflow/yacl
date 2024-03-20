// Copyright 2019 Ant Group Co., Ltd.
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

#include "yacl/crypto/sign/sm2_signing.h"

#include <string>

#include "gtest/gtest.h"

#include "yacl/crypto/openssl_wrappers.h"

namespace yacl::crypto {

TEST(Sm2Signing, SignVerify_shouldOk) {
  // GIVEN
  auto [pk, sk] = GenSm2KeyPairToPemBuf();
  std::string plaintext = "I am a plaintext.";

  // WHEN & THEN
  auto S = Sm2Signer(sk);
  auto signature = S.Sign(plaintext);
  auto V = Sm2Verifier(pk);
  EXPECT_EQ(V.Verify(plaintext, signature), true);
}

TEST(Sm2Signing, SignVerify_shouldFail_wrong_message) {
  // GIVEN
  auto [pk, sk] = GenSm2KeyPairToPemBuf();
  std::string plaintext = "I am a plaintext.";
  std::string faketext = "I am a faketext.";

  // WHEN & THEN
  auto S = Sm2Signer(sk);
  auto signature = S.Sign(plaintext);
  auto V = Sm2Verifier(pk);
  EXPECT_EQ(V.Verify(faketext, signature), false);
}

TEST(Sm2Signing, SignVerify_shouldFail_wrong_signature) {
  // GIVEN
  auto [pk, sk] = GenSm2KeyPairToPemBuf();
  std::string plaintext = "I am a plaintext.";
  std::string faketext = "I am a faketext.";

  // WHEN & THEN
  auto S = Sm2Signer(sk);
  auto fake_signature = S.Sign(faketext);
  auto V = Sm2Verifier(pk);
  EXPECT_EQ(V.Verify(plaintext, fake_signature), false);
}

TEST(Sm2Signing, SignVerify_shouldFail_wrong_key) {
  // GIVEN
  auto [pk1, sk1] = GenSm2KeyPairToPemBuf();
  auto [pk2, sk2] = GenSm2KeyPairToPemBuf();

  std::string plaintext = "I am a plaintext.";

  // WHEN & THEN
  auto S = Sm2Signer(sk1);
  auto signature = S.Sign(plaintext);
  auto V = Sm2Verifier(pk2);
  EXPECT_EQ(V.Verify(plaintext, signature), false);
}

TEST(Sm2Signing, SignVerifyInitWithCert_shouldOk) {
  // GIVEN
  auto [pk_buf, sk_buf] = GenSm2KeyPairToPemBuf(); /* pkey */
  auto pk = LoadKeyFromBuf(pk_buf);
  auto sk = LoadKeyFromBuf(sk_buf);
  auto cert = MakeX509Cert(pk, sk,
                           {
                               {"C", "CN"},
                               {"ST", "ZJ"},
                               {"L", "HZ"},
                               {"O", "TEE"},
                               {"OU", "EGG"},
                               {"CN", "demo.trustedegg.com"},
                           },
                           3, HashAlgorithm::SM3);
  auto cert_buf = ExportX509CertToBuf(cert);

  std::string plaintext = "I am a plaintext.";

  // WHEN & THEN
  /* signer */
  auto S = Sm2Signer(sk_buf);
  auto signature = S.Sign(plaintext);

  /* verifier */
  auto cert_pk = LoadX509CertPublicKeyFromBuf(cert_buf);
  auto V = Sm2Verifier(std::move(cert_pk));
  EXPECT_EQ(V.Verify(plaintext, signature), true);
}

}  // namespace yacl::crypto
