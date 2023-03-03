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

#include "yacl/crypto/base/drbg/sm4_drbg.h"

#include <algorithm>
#include <string>
#include <vector>

#include "absl/strings/escaping.h"
#include "openssl/aes.h"
#include "openssl/crypto.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "spdlog/spdlog.h"

#include "yacl/base/int128.h"

namespace yacl::crypto {

namespace {
const EVP_CIPHER* GetEvpCipher(SymmetricCrypto::CryptoType type) {
  switch (type) {
    case SymmetricCrypto::CryptoType::AES128_ECB:
      return EVP_aes_128_ecb();
    case SymmetricCrypto::CryptoType::AES128_CTR:
      return EVP_aes_128_ctr();
    case SymmetricCrypto::CryptoType::SM4_ECB:
      return EVP_sm4_ecb();
    case SymmetricCrypto::CryptoType::SM4_CTR:
      return EVP_sm4_ctr();
    default:
      YACL_THROW("unknown crypto type: {}", static_cast<int>(type));
  }
}
}  // namespace

void Sm4Drbg::Instantiate(ByteContainerView personal_string) {
  min_entropy_ = min_length_;

  // Get Entrpoy
  entropy_input_ = entropy_source_->GetEntropy(min_entropy_);

  seed_material_ = entropy_input_;

  std::string personal_buffer(personal_string.begin(), personal_string.end());
  seed_material_.append(personal_buffer);

  seed_material_ = RngDf(seed_material_);

  std::memset(key_.data(), 0, key_.size());
  std::memset(v_.data(), 0, key_.size());

  const EVP_CIPHER* cipher = GetEvpCipher(crypto_type_);

  YACL_ENFORCE(
      EVP_CipherInit_ex(ecb_ctx_.get(), cipher, NULL, key_.data(), NULL, 1));

  RngUpdate();

  reseed_counter_ = 1;

  return;
}

std::string Sm4Drbg::RngDf(ByteContainerView seed_material) {
  std::vector<uint8_t> s(seed_length_ + 9, 0x80);
  size_t inlen = seed_material.size();

  uint8_t* p = reinterpret_cast<uint8_t*>(&s[0]);

  *p++ = (inlen >> 24) & 0xff;
  *p++ = (inlen >> 16) & 0xff;
  *p++ = (inlen >> 8) & 0xff;
  *p++ = inlen & 0xff;

  /* NB keylen is at most 32 bytes */
  *p++ = 0;
  *p++ = 0;
  *p++ = 0;
  *p++ = (unsigned char)((2 * kBlockSize) & 0xff);
  std::memcpy(p, seed_material.data(), seed_material.length());

  std::array<uint8_t, kBlockSize> key = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                         0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                         0x0c, 0x0d, 0x0e, 0x0f};

  std::vector<uint8_t> iv0(kBlockSize), iv1(kBlockSize);
  std::memset(iv0.data(), 0, iv0.size());
  std::memset(iv1.data(), 0, iv1.size());
  iv1[3] = 1;
  iv0.insert(iv0.end(), s.begin(), s.end());
  iv1.insert(iv1.end(), s.begin(), s.end());

  std::array<uint8_t, kBlockSize> mac0 = CbcMac(key, iv0);
  std::array<uint8_t, kBlockSize> mac1 = CbcMac(key, iv1);

  std::string ret;

  EvpCipherPtr enc_ctx(EVP_CIPHER_CTX_new());
  EVP_CIPHER_CTX_init(enc_ctx.get());
  const EVP_CIPHER* cipher = GetEvpCipher(crypto_type_);

  YACL_ENFORCE(
      EVP_CipherInit_ex(enc_ctx.get(), cipher, NULL, mac0.data(), NULL, 1));

  while (ret.length() < seed_length_) {
    std::string cipher(kBlockSize, '\0');
    int enc_out_len = kBlockSize;
    YACL_ENFORCE(EVP_CipherUpdate(enc_ctx.get(), (unsigned char*)cipher.data(),
                                  &enc_out_len, mac1.data(), mac1.size()));
    ret.append(cipher);
    std::memcpy(mac1.data(), cipher.data(), cipher.length());
  }

  return ret;
}

std::array<uint8_t, kBlockSize> Sm4Drbg::CbcMac(
    absl::Span<const uint8_t> key, absl::Span<const uint8_t> data_to_mac) {
  EvpCipherPtr ctx_cbc(EVP_CIPHER_CTX_new());
  EVP_CIPHER_CTX_init(ctx_cbc.get());

  const EVP_CIPHER* cipher = GetEvpCipher(crypto_type_);
  YACL_ENFORCE(
      EVP_CipherInit_ex(ctx_cbc.get(), cipher, NULL, key.data(), NULL, 1));

  std::array<uint8_t, kBlockSize> chaining_value;
  std::memset(chaining_value.data(), 0, chaining_value.size());

  size_t n = data_to_mac.size() / kBlockSize;

  for (size_t idx = 0; idx < n; ++idx) {
    absl::Span<const uint8_t> block =
        absl::MakeSpan(data_to_mac.data() + idx * kBlockSize, kBlockSize);
    std::array<uint8_t, kBlockSize> input_block;
    int enc_out_len = input_block.size();

    for (size_t j = 0; j < kBlockSize; ++j) {
      input_block[j] = block[j] ^ chaining_value[j];
    }

    YACL_ENFORCE(EVP_CipherUpdate(ctx_cbc.get(), chaining_value.data(),
                                  &enc_out_len, input_block.data(),
                                  input_block.size()));
  }

  return chaining_value;
}

// inc_128 openssl drbg
// https://github.com/openssl/openssl/blob/OpenSSL_1_1_1-stable/crypto/rand/drbg_ctr.c#L23
//
void Sm4Drbg::Inc128() {
  uint8_t* p = &v_[0];
  uint32_t n = kBlockSize, c = 1;

  do {
    --n;
    c += p[n];
    p[n] = (uint8_t)c;
    c >>= 8;
  } while (n);
}

void Sm4Drbg::RngUpdate() {
  reseed_counter_++;

  std::string temp;

  std::array<uint8_t, 2 * kBlockSize> enc_in;
  std::array<uint8_t, 2 * kBlockSize> enc_out;
  int enc_out_len = enc_out.size();

  Inc128();
  std::memcpy(&enc_in[0], v_.data(), kBlockSize);

  Inc128();
  std::memcpy(&enc_in[kBlockSize], v_.data(), kBlockSize);

  YACL_ENFORCE(EVP_CipherUpdate(ecb_ctx_.get(), enc_out.data(), &enc_out_len,
                                enc_in.data(), enc_in.size()));
  YACL_ENFORCE(enc_out_len == enc_in.size());

  for (int idx = 0; idx < enc_out_len; ++idx) {
    enc_out[idx] ^= seed_material_[idx];
  }

  std::memcpy(key_.data(), &enc_out[0], kBlockSize);
  std::memcpy(v_.data(), &enc_out[kBlockSize], kBlockSize);

  const EVP_CIPHER* cipher = GetEvpCipher(crypto_type_);

  YACL_ENFORCE(
      EVP_CipherInit_ex(ecb_ctx_.get(), cipher, NULL, key_.data(), NULL, 1));

  return;
}

void Sm4Drbg::ReSeed(absl::Span<const uint8_t> seed,
                     absl::Span<const uint8_t> additional_input) {
  min_entropy_ = min_length_;
  entropy_input_ = entropy_source_->GetEntropy(min_entropy_);

  std::vector<uint8_t> seed_material(entropy_input_.length());
  std::memcpy(seed_material.data(), entropy_input_.data(),
              entropy_input_.length());
  seed_material.insert(seed_material.end(), additional_input.begin(),
                       additional_input.end());

  seed_material_ = RngDf(seed_material);
  RngUpdate();

  reseed_counter_ = 1;
}

// ReSeed with no additional input
void Sm4Drbg::ReSeed(absl::Span<const uint8_t> seed) {
  std::vector<uint8_t> additional_input;

  return ReSeed(seed, additional_input);
}

// Generate with no additional input
std::vector<uint8_t> Sm4Drbg::Generate(size_t rand_length) {
  std::vector<uint8_t> additional_input;

  return Generate(rand_length, additional_input);
}

std::vector<uint8_t> Sm4Drbg::Generate(
    size_t rand_length, absl::Span<const uint8_t> additional_input) {
  YACL_ENFORCE(rand_length <= kBlockSize);

  if (reseed_counter_ > reseed_interval_) {
    entropy_input_ = entropy_source_->GetEntropy(min_entropy_);

    ReSeed(absl::MakeSpan(reinterpret_cast<uint8_t*>(entropy_input_.data()),
                          entropy_input_.length()),
           additional_input);
  }

  std::string df_add_input(seed_length_, '\0');
  if (additional_input.size() > 0) {
    df_add_input = RngDf(additional_input);
  }

  reseed_counter_++;

  Inc128();

  std::vector<uint8_t> ret(rand_length);
  std::vector<uint8_t> enc_out(df_add_input.length());

  int enc_out_len = enc_out.size();

  YACL_ENFORCE(EVP_CipherUpdate(ecb_ctx_.get(), enc_out.data(), &enc_out_len,
                                (const unsigned char*)df_add_input.data(),
                                df_add_input.length()));

  std::memcpy(ret.data(), enc_out.data(), rand_length);

  RngUpdate();

  return ret;
}

// override IDrbg FillPRandBytes
void Sm4Drbg::FillPRandBytes(absl::Span<uint8_t> out) {
  const size_t nbytes = out.size();

  if (nbytes > 0) {
    size_t block_size = (nbytes + kBlockSize - 1) / kBlockSize;
    for (size_t idx = 0; idx < block_size; ++idx) {
      size_t current_pos = idx * kBlockSize;
      size_t current_size = std::min(kBlockSize, nbytes - current_pos);
      std::vector<uint8_t> rand_buf = Generate(current_size);
      YACL_ENFORCE(rand_buf.size() == current_size);
      std::memcpy(out.data() + current_pos, rand_buf.data(), current_size);
    }
  }
}

}  // namespace yacl::crypto
