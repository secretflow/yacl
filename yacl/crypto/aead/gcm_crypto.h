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

#include "absl/types/span.h"

#include "yacl/base/byte_container_view.h"
#include "yacl/secparam.h"

/* security parameter declaration */
YACL_MODULE_DECLARE("aes_gcm", SecParam::C::k128, SecParam::S::INF);

namespace yacl::crypto {

enum class GcmCryptoSchema : int {
  AES128_GCM, /* security level = 128 */
  AES256_GCM, /* security level = 256 */
  // SM4_GCM /* TODO openssl 3.2 supports SM4 GCM */
};

// -------------
// GCM Interface
// -------------
class GcmCrypto {
 public:
  GcmCrypto(GcmCryptoSchema schema, ByteContainerView key, ByteContainerView iv)
      : schema_(schema),
        key_(key.begin(), key.end()),
        iv_(iv.begin(), iv.end()) {}

  // Encrypts `plaintext` into `ciphertext`.
  // For aes-128, mac size shall be 16 fixed size.
  void Encrypt(ByteContainerView plaintext, ByteContainerView aad,
               absl::Span<uint8_t> ciphertext, absl::Span<uint8_t> mac) const;

  // Decrypts `ciphertext` into `plaintext`.
  void Decrypt(ByteContainerView ciphertext, ByteContainerView aad,
               ByteContainerView mac, absl::Span<uint8_t> plaintext) const;

 private:
  const GcmCryptoSchema schema_;    // GCM crypto schema
  const std::vector<uint8_t> key_;  // Symmetric key
  const std::vector<uint8_t> iv_;   // Initialize vector
};

// ---------------
// Implementations
// ---------------
class Aes128GcmCrypto : public GcmCrypto {
 public:
  Aes128GcmCrypto(ByteContainerView key, ByteContainerView iv)
      : GcmCrypto(GcmCryptoSchema::AES128_GCM, key, iv) {}
};

class Aes256GcmCrypto : public GcmCrypto {
 public:
  Aes256GcmCrypto(ByteContainerView key, ByteContainerView iv)
      : GcmCrypto(GcmCryptoSchema::AES256_GCM, key, iv) {}
};

// class Sm4GcmCrypto : public GcmCrypto {
//  public:
//   Sm4GcmCrypto(ByteContainerView key, ByteContainerView iv)
//       : GcmCrypto(GcmCryptoSchema::SM4_GCM, key, iv) {}
// };

/* to a string which openssl recognizes */
inline const char* ToString(GcmCryptoSchema scheme) {
  switch (scheme) {
    case GcmCryptoSchema::AES128_GCM:
      return "aes-128-gcm";
    case GcmCryptoSchema::AES256_GCM:
      return "aes-256-gcm";
    // case GcmCryptoSchema::SM4_GCM:
    //   return "sm4-gcm";
    default:
      YACL_THROW("Unsupported gcm scheme: {}", static_cast<int>(scheme));
  }
}

}  // namespace yacl::crypto
