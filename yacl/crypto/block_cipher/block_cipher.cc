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

#include "yacl/crypto/block_cipher/block_cipher.h"

#include <algorithm>
#include <climits>
#include <iterator>

#include "spdlog/spdlog.h"

#include "yacl/base/exception.h"
#include "yacl/crypto/openssl_wrappers.h"

namespace yacl::crypto {
namespace {

void SetupEVPCipherCtx(openssl::UniqueCipherCtx* ctx, BlockCipher::Mode type,
                       uint128_t key, uint128_t iv, int enc) {
  // This uses AES-128, so the key must be 128 bits.
  const auto cipher = openssl::FetchEvpCipher(ToString(type));
  YACL_ENFORCE(sizeof(key) == EVP_CIPHER_key_length(cipher.get()));
  const auto* key_data = reinterpret_cast<const uint8_t*>(&key);
  const auto* iv_data = reinterpret_cast<const uint8_t*>(&iv);

  // Don't set key or IV right away; we want to check lengths
  // see: https://www.openssl.org/docs/man3.0/man3/EVP_CipherFinal.html
  //
  // NOTE: key is the symmetric key to use and iv is the IV to use (if
  // necessary), the actual number of bytes used for the key and IV depends on
  // the cipher.
  OSSL_RET_1(EVP_CipherInit_ex2(ctx->get(), cipher.get(), nullptr, nullptr, enc,
                                nullptr));
  YACL_ENFORCE_EQ(EVP_CIPHER_CTX_get_key_length(ctx->get()), 16);
  if (type != BlockCipher::Mode::AES128_ECB &&
      type != BlockCipher::Mode::SM4_ECB) {
    YACL_ENFORCE_EQ(EVP_CIPHER_CTX_get_iv_length(ctx->get()), 16);
  }

  // Now we can set key and IV
  OSSL_RET_1(EVP_CipherInit_ex2(ctx->get(), cipher.get(), key_data, iv_data,
                                enc, nullptr));

  // No padding needed for aligned blocks.
  OSSL_RET_1(EVP_CIPHER_CTX_set_padding(ctx->get(), 0));
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

BlockCipher::BlockCipher(Mode type, uint128_t key, uint128_t iv)
    : type_(type), key_(key), iv_(iv) {
  // Init openssl encryption/decryption context
  enc_ctx_ = openssl::UniqueCipherCtx(EVP_CIPHER_CTX_new());
  dec_ctx_ = openssl::UniqueCipherCtx(EVP_CIPHER_CTX_new());

  SetupEVPCipherCtx(&enc_ctx_, type_, key_, iv_, 1);
  SetupEVPCipherCtx(&dec_ctx_, type_, key_, iv_, 0);
}

BlockCipher::BlockCipher(Mode type, ByteContainerView key, ByteContainerView iv)
    : type_(type),
      key_(CopyDataAsUint128(key.data())),
      iv_(CopyDataAsUint128(iv.data())) {
  // Init openssl encryption/decryption context
  enc_ctx_ = openssl::UniqueCipherCtx(EVP_CIPHER_CTX_new());
  dec_ctx_ = openssl::UniqueCipherCtx(EVP_CIPHER_CTX_new());

  SetupEVPCipherCtx(&enc_ctx_, type_, key_, iv_, 1);
  SetupEVPCipherCtx(&dec_ctx_, type_, key_, iv_, 0);
}

void BlockCipher::Decrypt(absl::Span<const uint8_t> ciphertext,
                          absl::Span<uint8_t> plaintext) const {
  if ((type_ != BlockCipher::Mode::AES128_CTR) &&
      (type_ != BlockCipher::Mode::SM4_CTR)) {
    if (ciphertext.size() % BlockSize() != 0) {
      YACL_THROW("Requires size can be divided by block_size={}.", BlockSize());
    }
  }
  YACL_ENFORCE(plaintext.size() == ciphertext.size());

  EVP_CIPHER_CTX* ctx;
  ctx = dec_ctx_.get();

  EVP_CIPHER_CTX_set_padding(ctx, plaintext.size() % BlockSize());

  size_t out_length = 0;
  size_t in_offset = 0;

  size_t limit = ((size_t)1 << 31) - BlockSize();

  while (in_offset < ciphertext.size()) {
    auto step_length = static_cast<int>(
        std::min<size_t>(ciphertext.size() - in_offset, limit));
    int current_out_length;
    int rc = EVP_CipherUpdate(ctx, plaintext.data() + out_length,
                              &current_out_length,
                              ciphertext.data() + in_offset, step_length);
    YACL_ENFORCE(rc, "Fail to decrypt, rc={}", rc);
    in_offset += step_length;
    out_length += current_out_length;
  }

  // Does not require `Finalize` for aligned inputs.
  if (plaintext.size() % BlockSize() != 0) {
    int current_out_length;
    int rc = EVP_CipherFinal(ctx, plaintext.data() + out_length,
                             &current_out_length);
    YACL_ENFORCE(rc, "Fail to finalize decrypt, rc={}", rc);
  }
}

void BlockCipher::Encrypt(absl::Span<const uint8_t> plaintext,
                          absl::Span<uint8_t> ciphertext) const {
  if ((type_ != BlockCipher::Mode::AES128_CTR) &&
      (type_ != BlockCipher::Mode::SM4_CTR)) {
    if (ciphertext.size() % BlockSize() != 0) {
      YACL_THROW("Requires size can be divided by block_size={}.", BlockSize());
    }
  }
  YACL_ENFORCE(plaintext.size() == ciphertext.size());

  EVP_CIPHER_CTX* ctx;
  ctx = enc_ctx_.get();

  EVP_CIPHER_CTX_set_padding(ctx, ciphertext.size() % BlockSize());

  size_t out_length = 0;
  size_t in_offset = 0;
  size_t limit = ((size_t)1 << 31) - BlockSize();

  while (in_offset < plaintext.size()) {
    int step_length =
        static_cast<int>(std::min<size_t>(plaintext.size() - in_offset, limit));
    int current_out_length;
    int rc = EVP_CipherUpdate(ctx, ciphertext.data() + out_length,
                              &current_out_length, plaintext.data() + in_offset,
                              step_length);
    YACL_ENFORCE(rc, "Fail to encrypt, rc={}", rc);
    in_offset += step_length;
    out_length += current_out_length;
  }

  // Does not require `Finalize` for aligned inputs.
  if (ciphertext.size() % BlockSize() != 0) {
    int current_out_length;
    int rc = EVP_CipherFinal(ctx, ciphertext.data() + out_length,
                             &current_out_length);
    YACL_ENFORCE(rc, "Fail to finalize encrypt, rc={}", rc);
  }
}

uint128_t BlockCipher::Encrypt(uint128_t input) const {
  uint128_t ret;
  Encrypt(absl::Span<const uint8_t>(reinterpret_cast<const uint8_t*>(&input),
                                    sizeof(input)),
          absl::Span<uint8_t>(reinterpret_cast<uint8_t*>(&ret), sizeof(ret)));
  return ret;
}

uint128_t BlockCipher::Decrypt(uint128_t input) const {
  uint128_t ret;
  Decrypt(absl::Span<const uint8_t>(reinterpret_cast<const uint8_t*>(&input),
                                    sizeof(input)),
          absl::Span<uint8_t>(reinterpret_cast<uint8_t*>(&ret), sizeof(ret)));
  return ret;
}

void BlockCipher::Encrypt(absl::Span<const uint128_t> plaintext,
                          absl::Span<uint128_t> ciphertext) const {
  auto in = absl::Span<const uint8_t>(
      reinterpret_cast<const uint8_t*>(plaintext.data()),
      plaintext.size() * sizeof(uint128_t));
  auto out = absl::Span<uint8_t>(reinterpret_cast<uint8_t*>(ciphertext.data()),
                                 ciphertext.size() * sizeof(uint128_t));
  Encrypt(in, out);
}

void BlockCipher::Decrypt(absl::Span<const uint128_t> ciphertext,
                          absl::Span<uint128_t> plaintext) const {
  auto in = absl::Span<const uint8_t>(
      reinterpret_cast<const uint8_t*>(ciphertext.data()),
      ciphertext.size() * sizeof(uint128_t));
  auto out = absl::Span<uint8_t>(reinterpret_cast<uint8_t*>(plaintext.data()),
                                 plaintext.size() * sizeof(uint128_t));
  Decrypt(in, out);
}

void BlockCipher::Reset() {
  if (enc_ctx_ != nullptr) {
    // Clears all information from a cipher context and free up any allocated
    // memory associated with it, except the ctx itself. This function should be
    // called anytime ctx is reused by another EVP_CipherInit() /
    // EVP_CipherUpdate() / EVP_CipherFinal() series of calls.
    OSSL_RET_1(EVP_CIPHER_CTX_reset(enc_ctx_.get()));
    SetupEVPCipherCtx(&enc_ctx_, type_, key_, iv_, 1);
  }
  if (dec_ctx_ != nullptr) {
    OSSL_RET_1(EVP_CIPHER_CTX_reset(dec_ctx_.get()));
    SetupEVPCipherCtx(&dec_ctx_, type_, key_, iv_, 0);
  }
}

}  // namespace yacl::crypto
