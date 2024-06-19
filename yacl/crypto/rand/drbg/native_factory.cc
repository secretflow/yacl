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

#include "yacl/crypto/rand/drbg/native_factory.h"

#include <cstdint>
#include <ctime>
#include <iterator>
#include <limits>
#include <string>
#include <vector>

#include "absl/strings/escaping.h"
#include "openssl/aes.h"
#include "openssl/crypto.h"
#include "openssl/err.h"
#include "openssl/evp.h"

#include "yacl/base/byte_container_view.h"
#include "yacl/base/exception.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/block_cipher/symmetric_crypto.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/crypto/openssl_wrappers.h"
#include "yacl/crypto/rand/entropy_source/entropy_source.h"
#include "yacl/secparam.h"

namespace yacl::crypto {

NativeDrbg::NativeDrbg(std::string type, bool use_yacl_es, SecParam::C secparam)
    : type_(std::move(type)), secparam_(secparam) {
  YACL_ENFORCE(use_yacl_es == true);
  YACL_ENFORCE(secparam_ == SecParam::C::k128);
  drbg_impl_ = std::make_unique<internal::Sm4Drbg>();
  auto es = EntropySourceFactory::Instance().Create("auto");
  auto nonce = es->GetEntropy(32);
  drbg_impl_->Instantiate(nonce);
}

void NativeDrbg::Fill(char* buf, size_t len) {
  auto rand_buf = drbg_impl_->Generate(len);
  YACL_ENFORCE((int)len == rand_buf.size());
  std::memcpy(buf, rand_buf.data(), len);
}

namespace internal {

inline uint64_t GetCurrentTime() { return time(nullptr); }

Sm4Drbg::Sm4Drbg(SecParam::C secparam) {
  YACL_ENFORCE(secparam == SecParam::C::k128);
}

Sm4Drbg::Sm4Drbg(const SecParam::C& secparam) {
  YACL_ENFORCE(secparam == SecParam::C::k128);
}

void Sm4Drbg::Instantiate(ByteContainerView nonce,
                          ByteContainerView personal_string) {
  // by default, yacl can ensure that the exact number of bits are filled by
  // its entropy source
  auto es = EntropySourceFactory::Instance().Create("auto");

  // since GetEntrpoy always success in yacl, there is no need for step (c) in
  // the standard
  auto entropy_buf = es->GetEntropy(kMinEntropySize); /* 32 bytes */
  YACL_ENFORCE(entropy_buf.size() == kSeedlen);

  // initialize SM4 entryption context
  cipher_ = openssl::FetchEvpCipher(ToString(kCodeType));
  cipher_ctx_ = openssl::UniqueCipherCtx(EVP_CIPHER_CTX_new());

  // entropy_buf xor {H(nonce) || H(personal_string)}
  uint128_t lhf = Blake3_128(nonce);
  uint128_t rhf = Blake3_128(personal_string);
  *(entropy_buf.data<uint128_t>()) ^= lhf;
  *(entropy_buf.data<uint128_t>() + 1) ^= rhf;

  // derived_buf = Derive(entropy_buf || nonce || personal_string)
  // derived_buf has the same length as entropy_buf (32 bytes)
  auto derived_buf = derive(entropy_buf, kSeedlen);

  // reset internal state
  internal_state_.key = 0;
  internal_state_.v = 0;

  rng_update(derived_buf, internal_state_.key, internal_state_.v,
             &internal_state_.key, &internal_state_.v);

  internal_state_.reseed_ctr = 1;
  internal_state_.last_reseed_time = GetCurrentTime();
}

void Sm4Drbg::rng_update(ByteContainerView derived_buf, uint128_t key,
                         uint128_t v, uint128_t* out_key, uint128_t* out_v) {
  // make sure the input key has correct key length, then init cipher context
  YACL_ENFORCE(sizeof(key) == EVP_CIPHER_key_length(cipher_.get()));
  OSSL_RET_1(EVP_CIPHER_CTX_reset(cipher_ctx_.get()));
  YACL_ENFORCE(EVP_CipherInit(cipher_ctx_.get(), cipher_.get(),
                              (const unsigned char*)&key,
                              /* iv */ nullptr, /* 1 = enc, 0 = dec */ 1));
  static_assert(kSeedlen % kBlockSize == 0);

  Buffer temp(kSeedlen);
  for (size_t i = 0; i < kSeedlen / kBlockSize; ++i, ++v) {
    int out_len = 0;
    OSSL_RET_1(EVP_CipherUpdate(cipher_ctx_.get(),
                                temp.data<unsigned char>() + i * kBlockSize,
                                &out_len, (const unsigned char*)&v, sizeof(v)));
    YACL_ENFORCE(out_len == kBlockSize);
  }

  for (int i = 0; i < temp.size(); ++i) {
    *(temp.data<unsigned char>() + i) ^=
        *((unsigned char*)derived_buf.data() + i);
  }

  YACL_ENFORCE(temp.size() == kKeySize + kBlockSize);
  std::memcpy(out_key, temp.data<unsigned char>(), sizeof(uint128_t));
  std::memcpy(out_v, temp.data<unsigned char>() + sizeof(uint128_t),
              sizeof(uint128_t));
}

Buffer Sm4Drbg::derive(ByteContainerView buf,
                       /* out bytes */ uint32_t out_len) {
  /* the input buf size is at most 32 bytes */
  YACL_ENFORCE(buf.size() <= std::numeric_limits<uint32_t>::max());

  /* step (a) */
  uint32_t l = buf.size();

  /* step (b) */
  uint32_t n = out_len;

  /* step (c) */
  std::vector<uint8_t> s(sizeof(l) + sizeof(n) + buf.size() + 1, 0x00);
  auto* p = reinterpret_cast<uint8_t*>(s.data());
  *p++ = (l >> 24) & 0xff;  // set 1st byte of l
  *p++ = (l >> 16) & 0xff;  // set 2nd byte of l
  *p++ = (l >> 8) & 0xff;   // set 3rd byte of l
  *p++ = l & 0xff;          // set 4th byte of l

  *p++ = (n >> 24) & 0xff;  // set 1st byte of n
  *p++ = (n >> 16) & 0xff;  // set 2nd byte of n
  *p++ = (n >> 8) & 0xff;   // set 3rd byte of n
  *p++ = n & 0xff;          // set 4th byte of n

  std::memcpy(p, buf.data(), buf.size());  // set input_string
  p = p + kSeedlen;
  *p = 0x80;  // last bit

  s.resize(out_len, 0x00);

  /* step (e) */
  std::vector<uint8_t> temp;

  /* step (f) */
  uint32_t i = 0;

  /* step (g) */
  // 256 bits hex number =
  // 0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
  //
  // 128 bits hex number =
  // 0x000102030405060708090A0B0C0D0E0F
  uint128_t key = MakeUint128(0x0001020304050607, 0x08090A0B0C0D0E0F);

  /* step (h) */
  while (temp.size() < kKeySize + out_len) {
    /* step (h-1) */
    std::vector<uint8_t> iv(out_len, 0x00); /* inited to 0 */
    iv[0] = (i >> 24) & 0xff;               // set 1st byte of i
    iv[1] = (i >> 16) & 0xff;               // set 1st byte of i
    iv[2] = (i >> 8) & 0xff;                // set 1st byte of i
    iv[3] = i & 0xff;                       // set 1st byte of i

    /* step (h-2) */
    iv.insert(iv.end(), std::begin(s), std::end(s));
    auto mac = cbc_mac(key, iv);
    temp.insert(temp.end(), std::begin(mac), std::end(mac));

    /* step (h-3) */
    i++;
  }

  /* step (i) */
  absl::Span temp_span = absl::MakeSpan(temp);
  auto k = temp_span.subspan(0, kKeySize);        // span
  auto x = temp_span.subspan(kKeySize, out_len);  // span

  std::string ret;
  YACL_ENFORCE(sizeof(key) == EVP_CIPHER_key_length(cipher_.get()));
  OSSL_RET_1(EVP_CIPHER_CTX_reset(cipher_ctx_.get()));
  YACL_ENFORCE(EVP_CipherInit(cipher_ctx_.get(), cipher_.get(),
                              /* k as key */ k.data(),
                              /* sm4 iv = null */ nullptr,
                              /* 1 = enc, 0 = dec */ 1));

  /* step (l) */
  while (ret.size() < out_len) {
    std::string cipher(kBlockSize, '\0');
    EVP_CipherUpdate(cipher_ctx_.get(), (unsigned char*)cipher.data(), nullptr,
                     x.data(), x.size());
    ret.append(cipher);
  }

  YACL_ENFORCE(ret.size() >= out_len);
  return {ret.data(), out_len};
}

std::array<uint8_t, Sm4Drbg::kBlockSize> Sm4Drbg::cbc_mac(
    uint128_t key, ByteContainerView data) {
  static_assert(kSeedlen % kBlockSize == 0);

  /* init openssl cipher contex */
  OSSL_RET_1(EVP_CIPHER_CTX_reset(cipher_ctx_.get()));
  auto local_ctx = openssl::UniqueCipherCtx(EVP_CIPHER_CTX_new());
  YACL_ENFORCE(EVP_CipherInit(local_ctx.get(), cipher_.get(),
                              (const unsigned char*)&key,
                              /* iv */ nullptr, /* 1 = enc, 0 = dec */ 1));

  /* step (a) */
  std::array<uint8_t, kBlockSize> chaining_value{};  // defalt init to 0

  /* step (b) */
  size_t n = data.size() / kBlockSize;

  /* step (c-d) */
  for (size_t idx = 0; idx < n; ++idx) {
    absl::Span<const uint8_t> block =
        absl::MakeSpan(data.data() + idx * kBlockSize, kBlockSize);
    std::array<uint8_t, kBlockSize> input_block;
    int enc_out_len = input_block.size();

    for (size_t j = 0; j < kBlockSize; ++j) {
      input_block[j] = block[j] ^ chaining_value[j];
    }

    YACL_ENFORCE(EVP_CipherUpdate(local_ctx.get(), chaining_value.data(),
                                  &enc_out_len, input_block.data(),
                                  input_block.size()));
  }
  return chaining_value;
}

void Sm4Drbg::reseed(ByteContainerView additional_input) {
  // by default, yacl can ensure that the exact number of bits are filled by
  // its entropy source
  auto es = EntropySourceFactory::Instance().Create("auto");

  // GetEntrpoy always succeed in yacl
  auto buf = es->GetEntropy(kMinEntropySize); /* 32 bytes */

  // get the derived buf, shoud be at least 32 + 32 + 0 = 64 bytes
  // Derive(entropy_buf || nonce || personal_string)
  buf.resize(buf.size() + additional_input.size());
  std::memcpy((char*)buf.data() + kMinEntropySize, additional_input.data(),
              additional_input.size());
  auto derived_buf = derive(buf, kSeedlen);

  YACL_ENFORCE_EQ(buf.size(), kSeedlen);
  rng_update(derived_buf, internal_state_.key, internal_state_.v,
             &internal_state_.key, &internal_state_.v);

  internal_state_.reseed_ctr = 1;
  internal_state_.last_reseed_time = GetCurrentTime();
}

Buffer Sm4Drbg::Generate(size_t len, ByteContainerView additional_input) {
  YACL_ENFORCE(len <= kBlockSize);

  if (internal_state_.reseed_ctr > internal_state_.reseed_interval_ctr) {
    reseed(additional_input);
  }

  Buffer df_add_input(kSeedlen);
  if (!additional_input.empty()) {
    df_add_input = derive(additional_input, kSeedlen);
    rng_update(df_add_input, internal_state_.key, internal_state_.v,
               &internal_state_.key, &internal_state_.v);
  }

  internal_state_.reseed_ctr++;
  internal_state_.v++;

  Buffer ret(len);
  std::memset(ret.data(), 0, len);
  std::vector<uint8_t> enc_out(df_add_input.size());

  int out_len = 0;
  YACL_ENFORCE(EVP_CipherUpdate(cipher_ctx_.get(), enc_out.data(), &out_len,
                                (const unsigned char*)&internal_state_.v,
                                sizeof(internal_state_.v)));
  std::memcpy(ret.data(), enc_out.data(), len);

  if (!additional_input.empty()) {
    rng_update(additional_input, internal_state_.key, internal_state_.v,
               &internal_state_.key, &internal_state_.v);
  } else {
    rng_update(std::vector<uint8_t>(kSeedlen), internal_state_.key,
               internal_state_.v, &internal_state_.key, &internal_state_.v);
  }

  return ret;
}

}  // namespace internal
}  // namespace yacl::crypto
