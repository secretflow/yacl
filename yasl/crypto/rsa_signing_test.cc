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

#include "yasl/crypto/rsa_signing.h"

#include "gtest/gtest.h"
#include "openssl/pem.h"

#include "yasl/crypto/asymmetric_util.h"

namespace yasl::crypto {

TEST(RsaSigning, SignVerify_shouldOk) {
  // GIVEN
  auto [public_key, private_key] = CreateRsaKeyPair();
  std::string plaintext = "I am a plaintext.";

  // WHEN & THEN
  auto rsa_signer = RsaSigner::CreateFromPem(private_key);
  auto signature = rsa_signer->Sign(plaintext);

  auto rsa_verifier = RsaVerifier::CreateFromPem(public_key);
  rsa_verifier->Verify(plaintext, signature);
}

TEST(RsaSigning, SignVerifyInitWithCert_shouldOk) {
  // GIVEN
  auto [cert, private_key] = CreateRsaCertificateAndPrivateKey(
      {
          {"C", "CN"},
          {"ST", "ZJ"},
          {"L", "HZ"},
          {"O", "TEE"},
          {"OU", "EGG"},
          {"CN", "demo.trustedegg.com"},
      },
      2048, 3);
  std::string plaintext = "I am a plaintext.";
  // WHEN & THEN
  auto rsa_signer = RsaSigner::CreateFromPem(private_key);
  auto signature = rsa_signer->Sign(plaintext);
  auto rsa_verifier = RsaVerifier::CreateFromCertPem(cert);
  rsa_verifier->Verify(plaintext, signature);
}

}  // namespace yasl::crypto