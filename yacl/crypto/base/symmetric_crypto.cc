// Copyright 2022 Ant Group Co., Ltd.
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

#include "yacl/crypto/base/symmetric_crypto.h"

#include <algorithm>
#include <iterator>

#include "openssl/aes.h"
#include "openssl/crypto.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "spdlog/spdlog.h"

#include "yacl/base/exception.h"

namespace yacl::crypto {
namespace {

const EVP_CIPHER* CreateEvpCipher(SymmetricCrypto::CryptoType type) {
  switch (type) {
    case SymmetricCrypto::CryptoType::AES128_ECB:
      return EVP_aes_128_ecb();
    case SymmetricCrypto::CryptoType::AES128_CBC:
      return EVP_aes_128_cbc();
    case SymmetricCrypto::CryptoType::AES128_CTR:
      return EVP_aes_128_ctr();
    case SymmetricCrypto::CryptoType::SM4_ECB:
      return EVP_sm4_ecb();
    case SymmetricCrypto::CryptoType::SM4_CBC:
      return EVP_sm4_cbc();
    case SymmetricCrypto::CryptoType::SM4_CTR:
      return EVP_sm4_ctr();
    default:
      YACL_THROW("unknown crypto type: {}", static_cast<int>(type));
  }
}

EVP_CIPHER_CTX* CreateEVPCipherCtx(SymmetricCrypto::CryptoType type,
                                   uint128_t key, uint128_t iv, int enc) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

  EVP_CIPHER_CTX_init(ctx);

  // This uses AES-128, so the key must be 128 bits.
  const EVP_CIPHER* cipher = CreateEvpCipher(type);
  YACL_ENFORCE(sizeof(key) == EVP_CIPHER_key_length(cipher));
  const auto* key_data = reinterpret_cast<const uint8_t*>(&key);

  // cbc mode need to set iv
  if ((type == SymmetricCrypto::CryptoType::AES128_ECB) ||
      (type == SymmetricCrypto::CryptoType::SM4_ECB)) {
    YACL_ENFORCE(
        EVP_CipherInit_ex(ctx, cipher, nullptr, key_data, nullptr, enc));
  } else {
    /**
     * @brief cbc and ctr mode set iv
     * for ctr the iv is the initiator counter, most case counter set 0
     */
    const auto* iv_data = reinterpret_cast<const uint8_t*>(&iv);
    YACL_ENFORCE(
        EVP_CipherInit_ex(ctx, cipher, nullptr, key_data, iv_data, enc));
  }

  // No padding needed for aligned blocks.
  YACL_ENFORCE(EVP_CIPHER_CTX_set_padding(ctx, 0));

  return ctx;
}

// int128 family requires alignment of 16, so we cannot just cast data into
// (u)int128_t and copy it.
uint128_t CopyDataAsUint128(const uint8_t* data) {
  uint128_t ret;
  for (size_t idx = 0; idx < sizeof(uint128_t); ++idx) {
    reinterpret_cast<uint8_t*>(&ret)[idx] = data[idx];
  }
  return ret;
}

}  // namespace

SymmetricCrypto::SymmetricCrypto(CryptoType type, uint128_t key, uint128_t iv)
    : type_(type), key_(key), initial_vector_(iv) {
  enc_ctx_ = CreateEVPCipherCtx(type_, key_, initial_vector_, 1);
  dec_ctx_ = CreateEVPCipherCtx(type_, key_, initial_vector_, 0);
}

SymmetricCrypto::SymmetricCrypto(CryptoType type, ByteContainerView key,
                                 ByteContainerView iv)
    : type_(type),
      key_(CopyDataAsUint128(key.data())),
      initial_vector_(CopyDataAsUint128(iv.data())) {
  enc_ctx_ = CreateEVPCipherCtx(type_, key_, initial_vector_, 1);
  dec_ctx_ = CreateEVPCipherCtx(type_, key_, initial_vector_, 0);
}

void SymmetricCrypto::Decrypt(absl::Span<const uint8_t> ciphertext,
                              absl::Span<uint8_t> plaintext) const {
  if ((type_ != SymmetricCrypto::CryptoType::AES128_CTR) &&
      (type_ != SymmetricCrypto::CryptoType::SM4_CTR)) {
    if (ciphertext.size() % BlockSize() != 0) {
      YACL_THROW("Requires size can be divided by block_size={}.", BlockSize());
    }
  }
  YACL_ENFORCE(plaintext.size() == ciphertext.size());

  EVP_CIPHER_CTX* ctx;
  if ((type_ == SymmetricCrypto::CryptoType::AES128_ECB) ||
      (type_ == SymmetricCrypto::CryptoType::SM4_ECB)) {
    ctx = dec_ctx_;
  } else {
    ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    EVP_CIPHER_CTX_copy(ctx, dec_ctx_);
  }

  EVP_CIPHER_CTX_set_padding(ctx, plaintext.size() % BlockSize());

  int out_length;
  int rc = EVP_CipherUpdate(ctx, plaintext.data(), &out_length,
                            ciphertext.data(), ciphertext.size());
  YACL_ENFORCE(rc, "Fail to decrypt, rc={}", rc);

  // Does not require `Finalize` for aligned inputs.
  if (plaintext.size() % BlockSize() != 0) {
    rc = EVP_CipherFinal(ctx, plaintext.data() + out_length, &out_length);
    YACL_ENFORCE(rc, "Fail to finalize decrypt, rc={}", rc);
  }

  if ((type_ != SymmetricCrypto::CryptoType::AES128_ECB) &&
      (type_ != SymmetricCrypto::CryptoType::SM4_ECB)) {
    EVP_CIPHER_CTX_free(ctx);
  }
}

void SymmetricCrypto::Encrypt(absl::Span<const uint8_t> plaintext,
                              absl::Span<uint8_t> ciphertext) const {
  if ((type_ != SymmetricCrypto::CryptoType::AES128_CTR) &&
      (type_ != SymmetricCrypto::CryptoType::SM4_CTR)) {
    if (ciphertext.size() % BlockSize() != 0) {
      YACL_THROW("Requires size can be divided by block_size={}.", BlockSize());
    }
  }
  YACL_ENFORCE(plaintext.size() == ciphertext.size());

  EVP_CIPHER_CTX* ctx;
  if ((type_ == SymmetricCrypto::CryptoType::AES128_ECB) ||
      (type_ == SymmetricCrypto::CryptoType::SM4_ECB)) {
    ctx = enc_ctx_;
  } else {
    ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    EVP_CIPHER_CTX_copy(ctx, enc_ctx_);
  }

  EVP_CIPHER_CTX_set_padding(ctx, ciphertext.size() % BlockSize());

  int outlen;
  int rc = EVP_CipherUpdate(ctx, ciphertext.data(), &outlen, plaintext.data(),
                            plaintext.size());
  YACL_ENFORCE(rc, "Fail to encrypt, rc={}", rc);

  // Does not require `Finalize` for aligned inputs.
  if (ciphertext.size() % BlockSize() != 0) {
    rc = EVP_CipherFinal(ctx, ciphertext.data() + outlen, &outlen);
    YACL_ENFORCE(rc, "Fail to finalize encrypt, rc={}", rc);
  }

  if ((type_ != SymmetricCrypto::CryptoType::AES128_ECB) &&
      (type_ != SymmetricCrypto::CryptoType::SM4_ECB)) {
    EVP_CIPHER_CTX_free(ctx);
  }
}

uint128_t SymmetricCrypto::Encrypt(uint128_t input) const {
  uint128_t ret;
  Encrypt(absl::Span<const uint8_t>(reinterpret_cast<const uint8_t*>(&input),
                                    sizeof(input)),
          absl::Span<uint8_t>(reinterpret_cast<uint8_t*>(&ret), sizeof(ret)));
  return ret;
}

uint128_t SymmetricCrypto::Decrypt(uint128_t input) const {
  uint128_t ret;
  Decrypt(absl::Span<const uint8_t>(reinterpret_cast<const uint8_t*>(&input),
                                    sizeof(input)),
          absl::Span<uint8_t>(reinterpret_cast<uint8_t*>(&ret), sizeof(ret)));
  return ret;
}

void SymmetricCrypto::Encrypt(absl::Span<const uint128_t> plaintext,
                              absl::Span<uint128_t> ciphertext) const {
  auto in = absl::Span<const uint8_t>(
      reinterpret_cast<const uint8_t*>(plaintext.data()),
      plaintext.size() * sizeof(uint128_t));
  auto out = absl::Span<uint8_t>(reinterpret_cast<uint8_t*>(ciphertext.data()),
                                 ciphertext.size() * sizeof(uint128_t));
  Encrypt(in, out);
}

void SymmetricCrypto::Decrypt(absl::Span<const uint128_t> ciphertext,
                              absl::Span<uint128_t> plaintext) const {
  auto in = absl::Span<const uint8_t>(
      reinterpret_cast<const uint8_t*>(ciphertext.data()),
      ciphertext.size() * sizeof(uint128_t));
  auto out = absl::Span<uint8_t>(reinterpret_cast<uint8_t*>(plaintext.data()),
                                 plaintext.size() * sizeof(uint128_t));
  Decrypt(in, out);
}

}  // namespace yacl::crypto
