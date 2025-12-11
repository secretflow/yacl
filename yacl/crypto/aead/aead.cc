// Copyright 2024 Ant Group Co., Ltd.
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

#include "yacl/crypto/aead/aead.h"

#include "yacl/crypto/aead/all_gcm.h"
#include "yacl/crypto/aead/sm4_mte.h"

namespace yacl::crypto {

size_t AeadCtx::GetKeySize(AeadAlgorithm algorithm) {
  switch (algorithm) {
    case AeadAlgorithm::AES128_GCM:
      return kAes128GcmKeySize;
    case AeadAlgorithm::AES256_GCM:
      return kAes256GcmKeySize;
#ifdef YACL_WITH_TONGSUO
    case AeadAlgorithm::SM4_GCM:
      return kSm4GcmKeySize;
#endif
    case AeadAlgorithm::SM4_MTE_HMAC_SM3:
      return kSm4MteKeySize;
    case AeadAlgorithm::UNKNOWN:
      YACL_THROW("It seems you have set AeadAlgorithm::UNKNOWN, aborting");
    default:
      YACL_THROW("Unknown AeadAlgorithm");
  }
}

size_t AeadCtx::GetMacSize(AeadAlgorithm algorithm) {
  switch (algorithm) {
    case AeadAlgorithm::AES128_GCM:
      return kAes128GcmKeySize;
    case AeadAlgorithm::AES256_GCM:
      return kAes256GcmKeySize;
#ifdef YACL_WITH_TONGSUO
    case AeadAlgorithm::SM4_GCM:
      return kSm4GcmKeySize;
#endif
    case AeadAlgorithm::SM4_MTE_HMAC_SM3:
      return kSm4MteMacCipherSize;
    case AeadAlgorithm::UNKNOWN:
      YACL_THROW("It seems you have set AeadAlgorithm::UNKNOWN, aborting");
    default:
      YACL_THROW("Unknown AeadAlgorithm");
  }
}

// Encrypts plaintext into ciphertext and mac. The input arguments
// are the AEAD algorithm, the plaintext,  and the optional
// additional-authenticated-data (aad).
void AeadCtx::Encrypt(ByteContainerView plaintext, ByteContainerView key,
                      ByteContainerView iv, absl::Span<uint8_t> ciphertext,
                      absl::Span<uint8_t> mac, ByteContainerView aad) const {
  Encrypt(algorithm_, plaintext, key, iv, ciphertext, mac, aad);
}

// Decrypts ciphertext and mac into ciphertext. The input
// arguments are the AEAD algorithm, the ciphertext, the mac,and the optional
// additional-authenticated-data (aad).
void AeadCtx::Decrypt(ByteContainerView ciphertext, ByteContainerView mac,
                      ByteContainerView key, ByteContainerView iv,
                      absl::Span<uint8_t> plaintext,
                      ByteContainerView aad) const {
  Decrypt(algorithm_, ciphertext, mac, key, iv, plaintext, aad);
}

// Statically encrypts plaintext into ciphertext and mac. The input arguments
// are the AEAD algorithm, the plaintext, the symmetric encryption key, the
// initialization vector (iv), and the optional additional-authenticated-data
// (aad).
void AeadCtx::Encrypt(AeadAlgorithm algorithm, ByteContainerView plaintext,
                      ByteContainerView key, ByteContainerView iv,
                      absl::Span<uint8_t> ciphertext, absl::Span<uint8_t> mac,
                      ByteContainerView aad) {
  YACL_ENFORCE(algorithm != AeadAlgorithm::UNKNOWN);
  switch (algorithm) {
    case AeadAlgorithm::AES128_GCM: {
      GcmCrypto(GcmCryptoSchema::AES128_GCM, key, iv)
          .Encrypt(plaintext, aad, ciphertext, mac);
      break;
    }
    case AeadAlgorithm::AES256_GCM: {
      GcmCrypto(GcmCryptoSchema::AES256_GCM, key, iv)
          .Encrypt(plaintext, aad, ciphertext, mac);
      break;
    }
#ifdef YACL_WITH_TONGSUO
    case AeadAlgorithm::SM4_GCM: {
      GcmCrypto(GcmCryptoSchema::SM4_GCM, key, iv)
          .Encrypt(plaintext, aad, ciphertext, mac);
      break;
    }
#endif
    case AeadAlgorithm::SM4_MTE_HMAC_SM3: {
      // cipher is in the form of Enc(hmac || plaintext)
      auto cipher = Sm4MteEncrypt(key, iv, plaintext);
      YACL_ENFORCE_EQ(cipher.size(), ciphertext.size());
      memcpy(ciphertext.data(), cipher.data(), cipher.size());
      break;
    }
    case AeadAlgorithm::UNKNOWN: {
      YACL_THROW("It seems you have set AeadAlgorithm::UNKNOWN, aborting");
      break;
    }
    default:
      YACL_THROW("Unknown AeadAlgorithm");
  }
}

// Statically decrypts ciphertext and mac into ciphertext. The input
// arguments are the AEAD algorithm, the ciphertext, the mac, the symmetric
// encryption key, the initialization vector (iv), and the optional
// additional-authenticated-data (aad).
void AeadCtx::Decrypt(AeadAlgorithm algorithm, ByteContainerView ciphertext,
                      ByteContainerView mac, ByteContainerView key,
                      ByteContainerView iv, absl::Span<uint8_t> plaintext,
                      ByteContainerView aad) {
  YACL_ENFORCE(algorithm != AeadAlgorithm::UNKNOWN);
  switch (algorithm) {
    case AeadAlgorithm::AES128_GCM:
      GcmCrypto(GcmCryptoSchema::AES128_GCM, key, iv)
          .Decrypt(ciphertext, aad, mac, plaintext);
      break;
    case AeadAlgorithm::AES256_GCM:
      GcmCrypto(GcmCryptoSchema::AES256_GCM, key, iv)
          .Decrypt(ciphertext, aad, mac, plaintext);
      break;
#ifdef YACL_WITH_TONGSUO
    case AeadAlgorithm::SM4_GCM: {
      GcmCrypto(GcmCryptoSchema::SM4_GCM, key, iv)
          .Decrypt(ciphertext, aad, mac, plaintext);
      break;
    }
#endif
    case AeadAlgorithm::SM4_MTE_HMAC_SM3: {
      // cipher is in the form of Enc(hmac || plaintext)
      auto plain = Sm4MteDecrypt(key, iv, ciphertext);
      YACL_ENFORCE_EQ(plain.size(), plaintext.size());
      memcpy(plaintext.data(), plain.data(), plain.size());
      break;
    }
    case AeadAlgorithm::UNKNOWN: {
      YACL_THROW("It seems you have set AeadAlgorithm::UNKNOWN, aborting");
      break;
    }
    default:
      YACL_THROW("Unknown AeadAlgorithm");
  }
}

}  // namespace yacl::crypto
