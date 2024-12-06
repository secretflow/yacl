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

#include "absl/types/span.h"

#include "yacl/base/byte_container_view.h"

namespace yacl::crypto {

// =============================================
// AEAD: Authenticated Encryption And Decryption
// =============================================
//
// AEAD provides confidentiality by encrypting the data with a symmetric
// encryption algorithm, and provides authenticity by using a MAC tag over the
// encrypted data.
//
// Related standards:
// + https://datatracker.ietf.org/doc/html/rfc5116
//
// NOTE Strictly, mac-then-encrypt algorithm is not aead, we add those
// algorithms only for backword compatiability.

enum class AeadAlgorithm : int {
  UNKNOWN = 0,
  AES128_GCM = 1,  // Galois-Counter Mode
  AES256_GCM = 2,  // Galois-Counter Mode
#ifdef YACL_WITH_TONGSUO
  SM4_GCM = 3,  // NOTE only Yacl built with gm mode supports this feature
#endif
  SM4_MTE_HMAC_SM3 = 4,  // Mac-Then-Encrypt with SM4 counter mode
};

// Pre-defined default Aead algorithm for AeadCtx only
constexpr AeadAlgorithm kDefaultAeadAlgorithm = AeadAlgorithm::AES128_GCM;

// AEAD Context Class
class AeadCtx {
 public:
  // Constructors
  AeadCtx();
  explicit AeadCtx(AeadAlgorithm algorithm) { SetAlgorithm(algorithm); }

  // Get a default AeadCtx with the AeadAlgorithm set. This function could be
  // seen as a helper function if you do not know which algorithm to choose.
  // Yacl recommend the use of GetDefault().
  static AeadCtx& GetDefault() {
    static AeadCtx ctx(kDefaultAeadAlgorithm);
    return ctx;
  }

  // Get the key size of the AEAD algorithm that is stored insize AeadCtx
  size_t GetKeySize() {
    YACL_ENFORCE(algorithm_ != AeadAlgorithm::UNKNOWN);
    return GetKeySize(algorithm_);
  }

  // Staticlly get the key size of an AEAD algorithm
  static size_t GetKeySize(AeadAlgorithm algorithm);

  // Get the mac size of the AEAD algorithm that is stored insize AeadCtx
  //
  // NOTE in case of mac-then-encrypt algorithm, this function fetches the
  // encrypted mac size
  size_t GetMacSize() {
    YACL_ENFORCE(algorithm_ != AeadAlgorithm::UNKNOWN);
    return GetMacSize(algorithm_);
  }

  // Staticlly get the mac size of an AEAD algorithm
  //
  // NOTE in case of mac-then-encrypt algorithm, this function fetches the
  // encrypted mac size
  static size_t GetMacSize(AeadAlgorithm algorithm);

  AeadAlgorithm GetAlgorithm() { return algorithm_; }
  void SetAlgorithm(AeadAlgorithm algorithm) { algorithm_ = algorithm; }

  // Encrypts plaintext into ciphertext and mac. The input arguments
  // are the AEAD algorithm, the plaintext,  and the optional
  // additional-authenticated-data (aad).
  //
  // NOTE Since Mac-Then-Encrypt results in one ciphertext, the argument "mac"
  // is ignored for Mte algorithms
  void Encrypt(ByteContainerView plaintext, ByteContainerView key,
               ByteContainerView iv, absl::Span<uint8_t> ciphertext,
               absl::Span<uint8_t> mac, ByteContainerView aad = "") const;

  // Decrypts ciphertext and mac into ciphertext. The input arguments are the
  // AEAD algorithm, the ciphertext, the mac,and the optional
  // additional-authenticated-data (aad).
  //
  // NOTE Since Mac-Then-Encrypt results in one ciphertext, the argument "mac"
  // is ignored for Mte algorithms
  void Decrypt(ByteContainerView ciphertext, ByteContainerView mac,
               ByteContainerView key, ByteContainerView iv,
               absl::Span<uint8_t> plaintext, ByteContainerView aad = "") const;

  // Staticlly encrypts plaintext into ciphertext and mac. The input arguments
  // are the AEAD algorithm, the plaintext, the symmetric encryption key, the
  // initialization vector (iv), and the optional additional-authenticated-data
  // (aad).
  //
  // NOTE Since Mac-Then-Encrypt results in one ciphertext, the argument "mac"
  // is ignored for Mte algorithms
  static void Encrypt(AeadAlgorithm algorithm, ByteContainerView plaintext,
                      ByteContainerView key, ByteContainerView iv,
                      absl::Span<uint8_t> ciphertext, absl::Span<uint8_t> mac,
                      ByteContainerView aad = "");

  // Staticlly decrypts ciphertext and mac into ciphertext. The input
  // arguments are the AEAD algorithm, the ciphertext, the mac, the symmetric
  // encryption key, the initialization vector (iv), and the optional
  // additional-authenticated-data (aad).
  //
  // NOTE Since Mac-Then-Encrypt results in one ciphertext, the argument "mac"
  // is ignored for Mte algorithms
  static void Decrypt(AeadAlgorithm algorithm, ByteContainerView ciphertext,
                      ByteContainerView mac, ByteContainerView key,
                      ByteContainerView iv, absl::Span<uint8_t> plaintext,
                      ByteContainerView aad = "");

 private:
  AeadAlgorithm algorithm_ = AeadAlgorithm::UNKNOWN;  // GCM crypto schema
};

}  // namespace yacl::crypto
