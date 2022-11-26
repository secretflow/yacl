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

#include "yacl/crypto/base/sm2_signing.h"

#include "gtest/gtest.h"
#include "openssl/pem.h"

#include "yacl/crypto/base/asymmetric_util.h"

namespace yacl::crypto {

TEST(Sm2Signing, SignVerify_shouldOk) {
  // GIVEN
  auto [public_key, private_key] = CreateSm2KeyPair();
  std::string plaintext = "I am a plaintext.";

  // WHEN & THEN
  auto sm2_signer = Sm2Signer::CreateFromPem(private_key);
  auto signature = sm2_signer->Sign(plaintext);

  auto sm2_verifier = Sm2Verifier::CreateFromPem(public_key);
  sm2_verifier->Verify(plaintext, signature);
}

}  // namespace yacl::crypto