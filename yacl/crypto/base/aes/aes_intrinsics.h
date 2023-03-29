//  Copyright (c) 1998-2002 The OpenSSL Project.  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions
//  are met:
//
//  1. Redistributions of source code must retain the above copyright
//   notice, this list of conditions and the following disclaimer.
//
//  2. Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//     distribution.
//
//  3. All advertising materials mentioning features or use of this
//     software must display the following acknowledgment:
//     "This product includes software developed by the OpenSSL Project
//     for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
//
//  4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
//     endorse or promote products derived from this software without
//     prior written permission. For written permission, please contact
//     openssl-core@openssl.org.
//
//  5. Products derived from this software may not be called "OpenSSL"
//      nor may "OpenSSL" appear in their names without prior written
//      permission of the OpenSSL Project.
//
//   6. Redistributions of any form whatsoever must retain the following
//      acknowledgment:
//      "This product includes software developed by the OpenSSL Project
//      for use in the OpenSSL Toolkit (http://www.openssl.org/)"
//
//  THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
//  EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
//  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
//  PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
//  ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
//  NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
//  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
//  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
//  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
//  OF THE POSSIBILITY OF SUCH DAMAGE.
//
// AES code mostly from, with additional support for uint128_t
// https://github.com/emp-toolkit/emp-tool/blob/master/emp-tool/utils/aes.h

#pragma once

#include <cstring>
#include <vector>

#include "absl/types/span.h"

#include "yacl/base/exception.h"
#include "yacl/base/int128.h"

#ifndef __aarch64__
// sse
#include <emmintrin.h>
#include <smmintrin.h>
// pclmul
#include <wmmintrin.h>
#else
#include "sse2neon.h"
#endif

namespace yacl::crypto {

namespace internal {
inline __m128i uint128_cast_m128i(uint128_t x) {
  auto tmp = DecomposeUInt128(x);
  return _mm_set_epi64x(tmp.first, tmp.second);
}

inline uint128_t m128i_cast_uint128(__m128i x) {
  uint128_t out;
  std::memcpy(&out, &x, sizeof(uint128_t));
  return out;
}
}  // namespace internal

struct AES_KEY {
  __m128i rd_key[11];
  unsigned int rounds;
};

// set aes encryption key
#define AES_EXPAND_ASSIST(v1, v2, v3, v4, shuff_const, aes_const)       \
  v2 = _mm_aeskeygenassist_si128(v4, aes_const);                        \
  v3 = _mm_castps_si128(                                                \
      _mm_shuffle_ps(_mm_castsi128_ps(v3), _mm_castsi128_ps(v1), 16));  \
  v1 = _mm_xor_si128(v1, v3);                                           \
  v3 = _mm_castps_si128(                                                \
      _mm_shuffle_ps(_mm_castsi128_ps(v3), _mm_castsi128_ps(v1), 140)); \
  v1 = _mm_xor_si128(v1, v3);                                           \
  v2 = _mm_shuffle_epi32(v2, shuff_const);                              \
  v1 = _mm_xor_si128(v1, v2)

inline void
#ifdef __x86_64__
    __attribute__((target("aes,sse2")))
#endif
    AES_set_encrypt_key(const __m128i userkey, AES_KEY *key) {
  __m128i x0;
  __m128i x1;
  __m128i x2;
  __m128i *kp = key->rd_key;
  kp[0] = x0 = userkey;
  x2 = _mm_setzero_si128();
  AES_EXPAND_ASSIST(x0, x1, x2, x0, 255, 1);
  kp[1] = x0;
  AES_EXPAND_ASSIST(x0, x1, x2, x0, 255, 2);
  kp[2] = x0;
  AES_EXPAND_ASSIST(x0, x1, x2, x0, 255, 4);
  kp[3] = x0;
  AES_EXPAND_ASSIST(x0, x1, x2, x0, 255, 8);
  kp[4] = x0;
  AES_EXPAND_ASSIST(x0, x1, x2, x0, 255, 16);
  kp[5] = x0;
  AES_EXPAND_ASSIST(x0, x1, x2, x0, 255, 32);
  kp[6] = x0;
  AES_EXPAND_ASSIST(x0, x1, x2, x0, 255, 64);
  kp[7] = x0;
  AES_EXPAND_ASSIST(x0, x1, x2, x0, 255, 128);
  kp[8] = x0;
  AES_EXPAND_ASSIST(x0, x1, x2, x0, 255, 27);
  kp[9] = x0;
  AES_EXPAND_ASSIST(x0, x1, x2, x0, 255, 54);
  kp[10] = x0;
  key->rounds = 10;
}

// encrypt blocks with given key
inline void
#ifdef __x86_64__
__attribute__((target("aes,sse2")))
#endif
AES_ecb_encrypt_blks(
    const __m128i *in_blks, __m128i *out_blks, size_t nblks,
    const AES_KEY *key) {
  for (size_t i = 0; i < nblks; ++i) {
    out_blks[i] = _mm_xor_si128(in_blks[i], key->rd_key[0]);
    for (size_t j = 1; j < key->rounds; ++j) {
      out_blks[i] = _mm_aesenc_si128(out_blks[i], key->rd_key[j]);
    }
    out_blks[i] = _mm_aesenclast_si128(out_blks[i], key->rd_key[key->rounds]);
  }
}

// (inplace) encrypt blocks with given key
#ifdef __GNUC__
#ifndef __clang__
#pragma GCC push_options
#pragma GCC optimize("unroll-loops")
#endif
#endif
template <int N>
inline void AES_ecb_encrypt_blks(const __m128i *in_blks, __m128i *out_blks,
                                 const AES_KEY *key) {
  AES_ecb_encrypt_blks(in_blks, out_blks, N, key);
}
#ifdef __GNUC_
#ifndef __clang___
#pragma GCC pop_options
#endif
#endif

inline void
#ifdef __x86_64__
    __attribute__((target("aes,sse2")))
#endif
    AES_set_decrypt_key_fast(AES_KEY *dkey, const AES_KEY *ekey) {
  int j = 0;
  int i = ekey->rounds;
#if (OCB_KEY_LEN == 0)
  dkey->rounds = i;
#endif
  dkey->rd_key[i--] = ekey->rd_key[j++];
  while (i != 0) {
    dkey->rd_key[i--] = _mm_aesimc_si128(ekey->rd_key[j++]);
  }
  dkey->rd_key[i] = ekey->rd_key[j];
}

inline void
#ifdef __x86_64__
    __attribute__((target("aes,sse2")))
#endif
    AES_set_decrypt_key(__m128i userkey, AES_KEY *key) {
  AES_KEY temp_key;
  AES_set_encrypt_key(userkey, &temp_key);
  AES_set_decrypt_key_fast(key, &temp_key);
}

inline void
#ifdef __x86_64__
    __attribute__((target("aes,sse2")))
#endif
    AES_ecb_decrypt_blks(const __m128i *in_blks, __m128i *out_blks,
                         unsigned nblks, const AES_KEY *key) {
  unsigned i = 0;
  unsigned j = 0;
  unsigned rnds = key->rounds;
  for (i = 0; i < nblks; ++i) {
    out_blks[i] = _mm_xor_si128(in_blks[i], key->rd_key[0]);
    for (j = 1; j < rnds; ++j) {
      out_blks[i] = _mm_aesdec_si128(out_blks[i], key->rd_key[j]);
    }
    out_blks[i] = _mm_aesdeclast_si128(out_blks[i], key->rd_key[j]);
  }
}

///////////////////////////////////////////////////////////////////
//                      uint128_t support                        //
///////////////////////////////////////////////////////////////////
inline void AES_set_encrypt_key(uint128_t userkey, AES_KEY *key) {
  auto tmp = internal::uint128_cast_m128i(userkey);
  AES_set_encrypt_key(tmp, key);
}

inline AES_KEY AES_set_encrypt_key(uint128_t userkey) {
  AES_KEY out;
  AES_set_encrypt_key(userkey, &out);
  return out;
}

inline void AES_set_decrypt_key(uint128_t userkey, AES_KEY *key) {
  auto tmp = internal::uint128_cast_m128i(userkey);
  AES_set_decrypt_key(tmp, key);
}

inline AES_KEY AES_set_decrypt_key(uint128_t userkey) {
  AES_KEY out;
  AES_set_decrypt_key(userkey, &out);
  return out;
}

inline void AES_ecb_encrypt_blks(const AES_KEY &key,
                                 absl::Span<const uint128_t> in_blks,
                                 absl::Span<uint128_t> out_blks) {
  YACL_ENFORCE_EQ(in_blks.size(), out_blks.size());
  const auto *in_ptr = reinterpret_cast<const __m128i *>(in_blks.data());
  auto *out_ptr = reinterpret_cast<__m128i *>(out_blks.data());
  AES_ecb_encrypt_blks(in_ptr, out_ptr, in_blks.size(), &key);
}

inline std::vector<uint128_t> AES_ecb_encrypt_blks(
    const AES_KEY &key, absl::Span<const uint128_t> in_blks) {
  std::vector<uint128_t> out(in_blks.size());
  AES_ecb_encrypt_blks(key, in_blks, absl::MakeSpan(out));
  return out;
}

// raw uint128_t pointer is a little bit faster
inline void AES_ecb_encrypt_blks(const AES_KEY &key, const uint128_t *in_blks,
                                 size_t blks_num, uint128_t *out_blks) {
  const auto *in_ptr = reinterpret_cast<const __m128i *>(in_blks);
  auto *out_ptr = reinterpret_cast<__m128i *>(out_blks);
  AES_ecb_encrypt_blks(in_ptr, out_ptr, blks_num, &key);
}

inline void AES_ecb_decrypt_blks(const AES_KEY &key,
                                 absl::Span<const uint128_t> in_blks,
                                 absl::Span<uint128_t> out_blks) {
  YACL_ENFORCE_EQ(in_blks.size(), out_blks.size());
  const auto *in_ptr = reinterpret_cast<const __m128i *>(in_blks.data());
  auto *out_ptr = reinterpret_cast<__m128i *>(out_blks.data());
  AES_ecb_decrypt_blks(in_ptr, out_ptr, in_blks.size(), &key);
}

inline std::vector<uint128_t> AES_ecb_decrypt_blks(
    const AES_KEY &key, absl::Span<const uint128_t> in_blks) {
  std::vector<uint128_t> out(in_blks.size());
  AES_ecb_decrypt_blks(key, in_blks, absl::MakeSpan(out));
  return out;
}

// raw uint128_t pointer is a little bit faster
inline void AES_ecb_decrypt_blks(const AES_KEY &key, const uint128_t *in_blks,
                                 size_t blks_num, uint128_t *out_blks) {
  const auto *in_ptr = reinterpret_cast<const __m128i *>(in_blks);
  auto *out_ptr = reinterpret_cast<__m128i *>(out_blks);
  AES_ecb_decrypt_blks(in_ptr, out_ptr, blks_num, &key);
}

}  // namespace yacl::crypto
