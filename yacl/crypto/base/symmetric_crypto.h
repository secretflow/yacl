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
#include "openssl/evp.h"

#include "yacl/base/byte_container_view.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/base/aes/aes_intrinsics.h"

namespace yacl::crypto {
namespace internal {

inline void EcbMakeContentBlocks(uint128_t count, absl::Span<uint128_t> buf) {
  std::iota(buf.begin(), buf.end(), count);
}

}  // namespace internal

// This class implements Symmetric- crypto.
class SymmetricCrypto {
 public:
  enum class CryptoType : int {
    AES128_ECB,
    AES128_CBC,
    AES128_CTR,
    SM4_ECB,
    SM4_CBC,
    SM4_CTR,
  };

  SymmetricCrypto(CryptoType type, uint128_t key, uint128_t iv = 0);
  SymmetricCrypto(CryptoType type, ByteContainerView key, ByteContainerView iv);

  ~SymmetricCrypto() {
    EVP_CIPHER_CTX_free(enc_ctx_);
    EVP_CIPHER_CTX_free(dec_ctx_);
  }

  // CBC Block Size.
  static constexpr int BlockSize() { return 128 / 8; }

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
  CryptoType GetType() const { return type_; }

 private:
  // Crypto type
  const CryptoType type_;
  // Symmetric key, 128 bits
  const uint128_t key_;

  // Initial vector cbc mode need
  const uint128_t initial_vector_;

  EVP_CIPHER_CTX* enc_ctx_;
  EVP_CIPHER_CTX* dec_ctx_;
};

class AesCbcCrypto : public SymmetricCrypto {
 public:
  AesCbcCrypto(uint128_t key, uint128_t iv)
      : SymmetricCrypto(SymmetricCrypto::CryptoType::AES128_CBC, key, iv) {}
};

class Sm4CbcCrypto : public SymmetricCrypto {
 public:
  Sm4CbcCrypto(uint128_t key, uint128_t iv)
      : SymmetricCrypto(SymmetricCrypto::CryptoType::SM4_CBC, key, iv) {}
};

// in some asymmetric scene
// may exist parties only need update count by buffer size.
template <typename T,
          std::enable_if_t<std::is_standard_layout<T>::value, int> = 0>
inline uint64_t DummyUpdateRandomCount(uint64_t count, absl::Span<T> out) {
  constexpr size_t block_size = SymmetricCrypto::BlockSize();
  const size_t nbytes = out.size() * sizeof(T);
  const size_t nblock = (nbytes + block_size - 1) / block_size;
  return count + nblock;
}

}  // namespace yacl::crypto
