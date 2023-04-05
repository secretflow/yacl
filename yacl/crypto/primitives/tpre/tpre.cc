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

#include <vector>

#include "yacl/crypto/base/aead/sm4_mac.h"
#include "yacl/crypto/primitives/tpre/capsule.h"

namespace yacl::crypto {

std::pair<std::unique_ptr<Capsule::CapsuleStruct>, std::vector<uint8_t>>
TPRE::Encrypt(std::unique_ptr<EcGroup> ecc_group,
              std::unique_ptr<Keys::PublicKey> pk_A, const std::string& iv,
              const std::string& plaintext) {
  Capsule capsule;

  std::pair<std::unique_ptr<Capsule::CapsuleStruct>, std::vector<uint8_t>>
      capsule_pair = capsule.EnCapsulate(std::move(ecc_group), std::move(pk_A));

  std::vector<uint8_t> ciphertext =
      yacl::crypto::Sm4MteEncrypt(capsule_pair.second, iv, plaintext);

  return {std::move(capsule_pair.first), ciphertext};
}

std::string TPRE::Decrypt(
    std::unique_ptr<EcGroup> ecc_group,
    std::unique_ptr<Capsule::CapsuleStruct> capsule_struct,
    const std::string& iv, std::vector<uint8_t> enc_data,
    std::unique_ptr<Keys::PrivateKey> sk_A) {
  Capsule capsule;
  std::vector<uint8_t> dek = capsule.DeCapsulate(
      std::move(ecc_group), std::move(sk_A), std::move(capsule_struct));

  std::string dek_str(dek.begin(), dek.end());
  std::vector<uint8_t> plaintext =
      yacl::crypto::Sm4MteDecrypt(dek_str, iv, enc_data);
  std::string plaintext_str(plaintext.begin(), plaintext.end());

  return plaintext_str;
}

std::pair<std::unique_ptr<Capsule::CFrag>, std::vector<uint8_t>>
TPRE::ReEncrypt(
    std::unique_ptr<EcGroup> ecc_group, std::unique_ptr<Keys::KFrag> kfrag,
    std::pair<std::unique_ptr<Capsule::CapsuleStruct>, std::vector<uint8_t>>
        ciphertext) {
  // New a capsule
  Capsule capsule;

  // Generate the cfrag
  std::unique_ptr<Capsule::CFrag> cfrag = capsule.ReEncapsulate(
      std::move(ecc_group), std::move(kfrag), std::move(ciphertext.first));

  // Define the re-encryption ciphertext, which includes cfrag and enc_data
  std::pair<std::unique_ptr<Capsule::CFrag>, std::vector<uint8_t>>
      re_ciphertext = {std::move(cfrag), ciphertext.second};

  return re_ciphertext;
}

std::string TPRE::DecryptFrags(
    std::unique_ptr<EcGroup> ecc_group, std::unique_ptr<Keys::PrivateKey> sk_B,
    std::unique_ptr<Keys::PublicKey> pk_A,
    std::unique_ptr<Keys::PublicKey> pk_B, const std::string& iv,
    std::pair<std::vector<std::unique_ptr<Capsule::CFrag>>,
              std::vector<uint8_t>>
        C_prime_set) {
  // New a capsule
  Capsule capsule;

  // Run DeCapsulateFrags algorithm, inputs cfrags' and private key of B,
  // outputs dek
  std::vector<uint8_t> dek = capsule.DeCapsulateFrags(
      std::move(ecc_group), std::move(sk_B), std::move(pk_A), std::move(pk_B),
      std::move(C_prime_set.first));

  // Decrypts ciphertext
  std::string dek_str(dek.begin(), dek.end());
  std::vector<uint8_t> plaintext =
      yacl::crypto::Sm4MteDecrypt(dek_str, iv, C_prime_set.second);
  std::string plaintext_str(plaintext.begin(), plaintext.end());

  return plaintext_str;
}
}  // namespace yacl::crypto