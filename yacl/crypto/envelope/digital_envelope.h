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

#pragma once

#include <vector>

#include "yacl/base/byte_container_view.h"

/* submodules */
#include "yacl/crypto/aead/gcm_crypto.h"
#include "yacl/crypto/aead/sm4_mac.h"
#include "yacl/crypto/block_cipher/symmetric_crypto.h"
#include "yacl/crypto/hash/ssl_hash.h"
#include "yacl/crypto/hmac/hmac_sm3.h"
#include "yacl/crypto/pke/asymmetric_rsa_crypto.h"
#include "yacl/crypto/pke/asymmetric_sm2_crypto.h"
#include "yacl/crypto/rand/rand.h"

namespace yacl::crypto {

// SM envelope sealing with sm4-ctr + hmac-sm3 + sm2.
//
// Input:
// - pub_key: sm2 public key
// - iv: initial vector
// - plaintext: plaintext to be sealed
//
// Output:
// - encrypted_key: the symmetric key encrypted by pub_key
// - ciphertext: the encryption of hmac + plaintext using SM4-CBC
void SmEnvSeal(ByteContainerView pub_key, ByteContainerView iv,
               ByteContainerView plaintext, std::vector<uint8_t>* encrypted_key,
               std::vector<uint8_t>* ciphertext);

// SM envelope open with sm4-cbc + hmac-sm3 + sm2.
//
// Input:
// - pri_key: sm2 private key
// - iv: initial vector
// - encrypted_key: the symmetric key encrypted by pub_key
// - ciphertext: the encrypted plaintext using SM4-CTR
// - hmac: hmac-sm3 of plaintext
//
// Output:
// - plaintext: the decryption of ciphertext using SM4-CTR
void SmEnvOpen(ByteContainerView pri_key, ByteContainerView iv,
               ByteContainerView encrypted_key, ByteContainerView ciphertext,
               std::vector<uint8_t>* plaintext);

/// Rsa envelope sealing with aes-128-gcm.
//
/// @param pub_key[in] rsa public key.
/// @param iv[in] initial vector.
/// @param plaintext[in] plaintext to be sealed.
/// @param encrypted_key[out] the symmetric key encrypted by pub_key.
/// @param ciphertext[out] the encrypted plaintext.
/// @param mac[out] the gcm mac.
void RsaEnvSeal(ByteContainerView pub_key, ByteContainerView iv,
                ByteContainerView plaintext,
                std::vector<uint8_t>* encrypted_key,
                std::vector<uint8_t>* ciphertext, std::vector<uint8_t>* mac);

/// Rsa envelope open with aes-128-gcm
///
/// @param pri_key[in] the rsa private key.
/// @param iv[in] the initial vector.
/// @param encrypted_key[in] the symmetric key encrypted by rsa public key.
/// @param ciphertext[in] the encrypted plaintext.
/// @param mac[in] the gcm mac.
/// @param plaintext[out] the decryption of ciphertext.
void RsaEnvOpen(ByteContainerView pri_key, ByteContainerView iv,
                ByteContainerView encrypted_key, ByteContainerView ciphertext,
                ByteContainerView mac, std::vector<uint8_t>* plaintext);

}  // namespace yacl::crypto
