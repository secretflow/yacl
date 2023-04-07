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

std::pair<Capsule::CapsuleStruct, std::vector<uint8_t>> TPRE::Encrypt(
    std::unique_ptr<EcGroup> ecc_group, std::unique_ptr<Keys::PublicKey> pk_A,
    const std::string& iv, const std::string& plaintext) {
  Capsule capsule;

  std::pair<Capsule::CapsuleStruct, std::vector<uint8_t>> capsule_pair =
      capsule.EnCapsulate(std::move(ecc_group), std::move(pk_A));

  std::vector<uint8_t> ciphertext =
      yacl::crypto::Sm4MteEncrypt(capsule_pair.second, iv, plaintext);

  return {capsule_pair.first, ciphertext};
}

std::string TPRE::Decrypt(
    const std::unique_ptr<EcGroup>& ecc_group,
    const std::unique_ptr<Capsule::CapsuleStruct>& capsule_struct,
    const std::string& iv, const std::vector<uint8_t>& enc_data,
    const std::unique_ptr<Keys::PrivateKey>& sk_A) const {
  std::unique_ptr<EcGroup> dup_ecc_group =
      EcGroupFactory::Create(ecc_group->GetCurveName());

  std::unique_ptr<Keys::PrivateKey> dup_sk_A =
      std::make_unique<Keys::PrivateKey>(*sk_A);

  std::unique_ptr<Capsule::CapsuleStruct> dup_capsule_struct =
      std::make_unique<Capsule::CapsuleStruct>(*capsule_struct);

  Capsule capsule;
  std::vector<uint8_t> dek =
      capsule.DeCapsulate(std::move(dup_ecc_group), std::move(dup_sk_A),
                          std::move(dup_capsule_struct));

  std::string dek_str(dek.begin(), dek.end());
  std::vector<uint8_t> plaintext =
      yacl::crypto::Sm4MteDecrypt(dek_str, iv, enc_data);
  std::string plaintext_str(plaintext.begin(), plaintext.end());

  return plaintext_str;
}

std::pair<Capsule::CFrag, std::vector<uint8_t>> TPRE::ReEncrypt(
    const std::unique_ptr<EcGroup>& ecc_group,
    const std::unique_ptr<Keys::KFrag>& kfrag,
    std::pair<const std::unique_ptr<Capsule::CapsuleStruct>&,
              const std::vector<uint8_t>&>
        ciphertext) const {
  // New a capsule
  Capsule capsule;

  std::unique_ptr<EcGroup> dup_ecc_group =
      EcGroupFactory::Create(ecc_group->GetCurveName());

  std::unique_ptr<Keys::KFrag> dup_kfrag =
      std::make_unique<Keys::KFrag>(*kfrag);

  std::unique_ptr<Capsule::CapsuleStruct> dup_capsule_struct =
      std::make_unique<Capsule::CapsuleStruct>(*(ciphertext.first));

  // Generate the cfrag
  Capsule::CFrag cfrag =
      capsule.ReEncapsulate(std::move(dup_ecc_group), std::move(dup_kfrag),
                            std::move(dup_capsule_struct));

  // Define the re-encryption ciphertext, which includes cfrag and enc_data
  std::pair<Capsule::CFrag, std::vector<uint8_t>> re_ciphertext = {
      cfrag, ciphertext.second};

  return re_ciphertext;
}

std::string TPRE::DecryptFrags(
    const std::unique_ptr<EcGroup>& ecc_group,
    const std::unique_ptr<Keys::PrivateKey>& sk_B,
    const std::unique_ptr<Keys::PublicKey>& pk_A,
    const std::unique_ptr<Keys::PublicKey>& pk_B, const std::string& iv,
    std::pair<const std::vector<std::unique_ptr<Capsule::CFrag>>&,
              const std::vector<uint8_t>&>
        C_prime_set) const {
  // New a capsule
  Capsule capsule;

  std::unique_ptr<EcGroup> dup_ecc_group =
      EcGroupFactory::Create(ecc_group->GetCurveName());

  std::unique_ptr<Keys::PrivateKey> dup_sk_B =
      std::make_unique<Keys::PrivateKey>(*sk_B);

  std::unique_ptr<Keys::PublicKey> dup_pk_A =
      std::make_unique<Keys::PublicKey>(*pk_A);

  std::unique_ptr<Keys::PublicKey> dup_pk_B =
      std::make_unique<Keys::PublicKey>(*pk_B);

  std::vector<std::unique_ptr<Capsule::CFrag>> dup_C_prime_set_first;
  for (const auto& element : C_prime_set.first) {
    std::unique_ptr<Capsule::CFrag> newElement(new Capsule::CFrag(*element));
    dup_C_prime_set_first.push_back(std::move(newElement));
  }

  // Run DeCapsulateFrags algorithm, inputs cfrags' and private key of B,
  // outputs dek
  std::vector<uint8_t> dek = capsule.DeCapsulateFrags(
      std::move(dup_ecc_group), std::move(dup_sk_B), std::move(dup_pk_A),
      std::move(dup_pk_B), std::move(dup_C_prime_set_first));

  // Decrypts ciphertext
  std::string dek_str(dek.begin(), dek.end());
  std::vector<uint8_t> plaintext =
      yacl::crypto::Sm4MteDecrypt(dek_str, iv, C_prime_set.second);
  std::string plaintext_str(plaintext.begin(), plaintext.end());

  return plaintext_str;
}
}  // namespace yacl::crypto
