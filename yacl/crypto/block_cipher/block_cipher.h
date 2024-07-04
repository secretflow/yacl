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

#include <cstdint>
#include <cstring>
#include <memory>
#include <numeric>
#include <string>
#include <vector>

#include "absl/types/span.h"

#include "yacl/base/byte_container_view.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/openssl_wrappers.h"
#include "yacl/secparam.h"

/* security parameter declaration */
YACL_MODULE_DECLARE("aes_all_modes", SecParam::C::k128, SecParam::S::INF);

namespace yacl::crypto {

// This class implements Symmetric- crypto.
class BlockCipher {
 public:
  // supported AES modes
  enum class Mode : int {
    AES128_ECB,  // ECB = Electronic Code Book
    AES128_CBC,  // CBC = Cipher Block Chaining
    AES128_CTR,  // CTR = Counter
    SM4_ECB,     // ECB = Electronic Code Book
    SM4_CBC,     // CBC = Cipher Block Chaining
    SM4_CTR,     // CTR = Counter
  };

  // constructor
  BlockCipher(Mode type, uint128_t key, uint128_t iv = 0);
  BlockCipher(Mode type, ByteContainerView key, ByteContainerView iv);

  // CBC Block Size.
  static constexpr int BlockSize() { return 128 / 8; }

  // Reset the internal contexts of BlockCipher (enc_ctx_, dec_ctx)
  // NOTE: key_, type_, and initial_vector_ stay unchanged
  void Reset();

  // Encrypts `plaintext` into `ciphertext`.
  // Note the ciphertext/plaintext size must be `N * kBlockSize`.
  void Encrypt(absl::Span<const uint8_t> plaintext,
               absl::Span<uint8_t> ciphertext) const;

  // Decrypts `ciphertext` into `plaintext`.
  // Note the ciphertext/plaintext size must be `N * kBlockSize`.
  void Decrypt(absl::Span<const uint8_t> ciphertext,
               absl::Span<uint8_t> plaintext) const;

  // Wrapper for uint128.
  uint128_t Encrypt(uint128_t input) const;
  uint128_t Decrypt(uint128_t input) const;

  // Wrapper for span<uint128>.
  void Encrypt(absl::Span<const uint128_t> plaintext,
               absl::Span<uint128_t> ciphertext) const;
  void Decrypt(absl::Span<const uint128_t> ciphertext,
               absl::Span<uint128_t> plaintext) const;

  // Getter
  Mode GetType() const { return type_; }

  //
  static void EcbMakeContentBlocks(uint128_t count, absl::Span<uint128_t> buf) {
    std::iota(buf.begin(), buf.end(), count);
  }

 private:
  const Mode type_;      //  Crypto type
  const uint128_t key_;  // Symmetric key, 128 bits
  const uint128_t iv_;   // Initialize vector

  // openssl cipher contexts
  openssl::UniqueCipherCtx enc_ctx_;
  openssl::UniqueCipherCtx dec_ctx_;
};

class AesCbcCrypto : public BlockCipher {
 public:
  AesCbcCrypto(uint128_t key, uint128_t iv)
      : BlockCipher(BlockCipher::Mode::AES128_CBC, key, iv) {}
};

class Sm4CbcCrypto : public BlockCipher {
 public:
  Sm4CbcCrypto(uint128_t key, uint128_t iv)
      : BlockCipher(BlockCipher::Mode::SM4_CBC, key, iv) {}
};

// in some asymmetric scene
// may exist parties only need update count by buffer size.
inline uint64_t DummyUpdateRandomCount(uint64_t count, size_t buffer_size) {
  constexpr size_t block_size = BlockCipher::BlockSize();
  const size_t nblock = (buffer_size + block_size - 1) / block_size;
  return count + nblock;
}

/* to a string which openssl recognizes */
inline const char* ToString(BlockCipher::Mode type) {
  switch (type) {
      // see: https://www.openssl.org/docs/manmaster/man7/EVP_CIPHER-AES.html
      // see: https://www.openssl.org/docs/man3.0/man7/EVP_CIPHER-SM4.html
    case BlockCipher::Mode::AES128_ECB:
      return "aes-128-ecb";
    case BlockCipher::Mode::AES128_CBC:
      return "aes-128-cbc";
    case BlockCipher::Mode::AES128_CTR:
      return "aes-128-ctr";
    case BlockCipher::Mode::SM4_ECB:
      return "sm4-ecb";
    case BlockCipher::Mode::SM4_CBC:
      return "sm4-cbc";
    case BlockCipher::Mode::SM4_CTR:
      return "sm4-ctr";
    default:
      YACL_THROW("Unsupported symmetric encryption algo: {}",
                 static_cast<int>(type));
  }
}

}  // namespace yacl::crypto
