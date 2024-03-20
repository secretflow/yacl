// Copyright 2023 Ant Group Co., Ltd.
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

#include "yacl/crypto/key_utils.h"

#include "gtest/gtest.h"

#include "yacl/crypto/pke/asymmetric_rsa_crypto.h"
#include "yacl/crypto/sign/rsa_signing.h"

namespace yacl::crypto {

TEST(KeyUtilsTest, PemFormat) {
  auto pkey = GenRsaKeyPair();
  ExportPublicKeyToPemFile(pkey, "tmp_pk.pem");
  ExportSecretKeyToPemBuf(pkey, "tmp_sk.pem");

  auto pk = LoadKeyFromFile("tmp_pk.pem");
  auto sk = LoadKeyFromFile("tmp_sk.pem");

  std::string m = "I am a plaintext.";

  auto enc_ctx = RsaEncryptor(std::move(pk));
  auto dec_ctx = RsaDecryptor(std::move(sk));

  auto c = enc_ctx.Encrypt(m);
  auto m_check = dec_ctx.Decrypt(c);

  // THEN
  EXPECT_EQ(std::memcmp(m.data(), m_check.data(), m.size()), 0);
}

TEST(KeyUtilsTest, DerFormat) {
  auto pkey = GenRsaKeyPair();
  ExportPublicKeyToDerFile(pkey, "tmp_pk.der");
  ExportSecretKeyToDerFile(pkey, "tmp_sk.der");

  auto pk = LoadKeyFromFile("tmp_pk.der");
  auto sk = LoadKeyFromFile("tmp_sk.der");

  std::string m = "I am a plaintext.";

  auto enc_ctx = RsaEncryptor(std::move(pk));
  auto dec_ctx = RsaDecryptor(std::move(sk));

  auto c = enc_ctx.Encrypt(m);
  auto m_check = dec_ctx.Decrypt(c);

  // THEN
  EXPECT_EQ(std::memcmp(m.data(), m_check.data(), m.size()), 0);
}

TEST(KeyUtilsTest, X508CertFormat) {
  auto [pk_buf, sk_buf] = GenRsaKeyPairToPemBuf(); /* pkey */
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
                           3, HashAlgorithm::SHA256);
  auto cert_buf = ExportX509CertToBuf(cert);

  std::string plaintext = "I am a plaintext.";

  // WHEN & THEN
  /* signer */
  auto S = RsaSigner(sk_buf);
  auto signature = S.Sign(plaintext);

  /* verifier */
  auto cert_pk = LoadX509CertPublicKeyFromBuf(cert_buf);
  auto V = RsaVerifier(std::move(cert_pk));
  EXPECT_TRUE(V.Verify(plaintext, signature));
}

}  // namespace yacl::crypto
