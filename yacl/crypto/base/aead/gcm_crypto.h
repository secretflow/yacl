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

namespace yacl::crypto {

enum class GcmCryptoSchema : int { AES128_GCM, AES256_GCM };

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
  // GCM crypto schema
  const GcmCryptoSchema schema_;
  // Symmetric key
  const std::vector<uint8_t> key_;
  // Initial vector
  const std::vector<uint8_t> iv_;
};

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
// TODO: Add SM4 GCM when openssl supports.

}  // namespace yacl::crypto