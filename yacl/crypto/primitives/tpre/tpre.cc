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
    const std::unique_ptr<EcGroup>& ecc_group, const Keys::PublicKey& pk_A,
    ByteContainerView iv, ByteContainerView plaintext) const {
  Capsule capsule;

  std::pair<Capsule::CapsuleStruct, std::vector<uint8_t>> capsule_pair =
      capsule.EnCapsulate(ecc_group, pk_A);

  std::vector<uint8_t> ciphertext =
      Sm4MteEncrypt(capsule_pair.second, iv, plaintext);

  return {capsule_pair.first, ciphertext};
}

std::string TPRE::Decrypt(const std::unique_ptr<EcGroup>& ecc_group,
                          const Capsule::CapsuleStruct& capsule_struct,
                          ByteContainerView iv,
                          const std::vector<uint8_t>& enc_data,
                          const Keys::PrivateKey& sk_A) const {
  Capsule capsule;
  std::vector<uint8_t> dek =
      capsule.DeCapsulate(ecc_group, sk_A, capsule_struct);

  std::vector<uint8_t> plaintext = Sm4MteDecrypt(dek, iv, enc_data);
  std::string plaintext_str(plaintext.begin(), plaintext.end());

  return plaintext_str;
}

std::pair<Capsule::CFrag, std::vector<uint8_t>> TPRE::ReEncrypt(
    const std::unique_ptr<EcGroup>& ecc_group, const Keys::KFrag& kfrag,
    const std::pair<Capsule::CapsuleStruct, std::vector<uint8_t>>& ciphertext)
    const {
  // New a capsule
  Capsule capsule;

  // Generate the cfrag
  Capsule::CFrag cfrag =
      capsule.ReEncapsulate(ecc_group, kfrag, ciphertext.first);

  // Define the re-encryption ciphertext, which includes cfrag and enc_data
  std::pair<Capsule::CFrag, std::vector<uint8_t>> re_ciphertext = {
      cfrag, ciphertext.second};

  return re_ciphertext;
}

std::string TPRE::DecryptFrags(
    const std::unique_ptr<EcGroup>& ecc_group, const Keys::PrivateKey& sk_B,
    const Keys::PublicKey& pk_A, const Keys::PublicKey& pk_B,
    ByteContainerView iv,
    const std::pair<std::vector<Capsule::CFrag>, std::vector<uint8_t>>&
        C_prime_set) const {
  // New a capsule
  Capsule capsule;

  // Run DeCapsulateFrags algorithm, inputs cfrags' and private key of B,
  // outputs dek

  std::vector<uint8_t> dek =
      capsule.DeCapsulateFrags(ecc_group, sk_B, pk_A, pk_B, C_prime_set.first);

  // Decrypts ciphertext
  std::vector<uint8_t> plaintext = Sm4MteDecrypt(dek, iv, C_prime_set.second);
  std::string plaintext_str(plaintext.begin(), plaintext.end());

  return plaintext_str;
}
}  // namespace yacl::crypto
