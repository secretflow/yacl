// MIT License
//
// Copyright (c) 2018 Xiao Wang (wangxiao1254@gmail.com)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// Enquiries about further applications and development opportunities are
// welcome.
//
// code mostly from
// https://github.com/emp-toolkit/emp-tool/blob/master/emp-tool/utils/aes_opt.h

#pragma once

#include "yacl/crypto/base/aes/aes_intrinsics.h"

namespace yacl::crypto {
template <int NumKeys>
static inline void ks_rounds(AES_KEY *keys, __m128i con, __m128i con3,
                             __m128i mask, int r) {
  for (int i = 0; i < NumKeys; ++i) {
    __m128i key = keys[i].rd_key[r - 1];
    __m128i x2 = _mm_shuffle_epi8(key, mask);
    __m128i aux = _mm_aesenclast_si128(x2, con);

    __m128i globAux = _mm_slli_epi64(key, 32);
    key = _mm_xor_si128(globAux, key);
    globAux = _mm_shuffle_epi8(key, con3);
    key = _mm_xor_si128(globAux, key);
    keys[i].rd_key[r] = _mm_xor_si128(aux, key);
  }
}
/*
 * AES key scheduling for 8 keys
 * [REF] Implementation of "Fast Garbling of Circuits Under Standard
 * Assumptions" https://eprint.iacr.org/2015/751.pdf
 */
template <int NumKeys>
static inline void AES_opt_key_schedule(__m128i *user_key, AES_KEY *keys) {
  __m128i con = _mm_set_epi32(1, 1, 1, 1);
  __m128i con2 = _mm_set_epi32(0x1b, 0x1b, 0x1b, 0x1b);
  __m128i con3 =
      _mm_set_epi32(0x07060504, 0x07060504, 0x0ffffffff, 0x0ffffffff);
  __m128i mask = _mm_set_epi32(0x0c0f0e0d, 0x0c0f0e0d, 0x0c0f0e0d, 0x0c0f0e0d);

  for (int i = 0; i < NumKeys; ++i) {
    keys[i].rounds = 10;
    keys[i].rd_key[0] = user_key[i];
  }

  ks_rounds<NumKeys>(keys, con, con3, mask, 1);
  con = _mm_slli_epi32(con, 1);
  ks_rounds<NumKeys>(keys, con, con3, mask, 2);
  con = _mm_slli_epi32(con, 1);
  ks_rounds<NumKeys>(keys, con, con3, mask, 3);
  con = _mm_slli_epi32(con, 1);
  ks_rounds<NumKeys>(keys, con, con3, mask, 4);
  con = _mm_slli_epi32(con, 1);
  ks_rounds<NumKeys>(keys, con, con3, mask, 5);
  con = _mm_slli_epi32(con, 1);
  ks_rounds<NumKeys>(keys, con, con3, mask, 6);
  con = _mm_slli_epi32(con, 1);
  ks_rounds<NumKeys>(keys, con, con3, mask, 7);
  con = _mm_slli_epi32(con, 1);
  ks_rounds<NumKeys>(keys, con, con3, mask, 8);
  ks_rounds<NumKeys>(keys, con2, con3, mask, 9);
  con2 = _mm_slli_epi32(con2, 1);
  ks_rounds<NumKeys>(keys, con2, con3, mask, 10);
}

/*
 * With numKeys keys, use each key to encrypt numEncs blocks.
 */
#ifdef __x86_64__
template <int numKeys, int numEncs>
static inline void ParaEnc(__m128i *blks, const AES_KEY *keys) {
  __m128i *first = blks;
  for (size_t i = 0; i < numKeys; ++i) {
    __m128i K = keys[i].rd_key[0];
    for (size_t j = 0; j < numEncs; ++j) {
      *blks = *blks ^ K;
      ++blks;
    }
  }

  for (unsigned int r = 1; r < 10; ++r) {
    blks = first;
    for (size_t i = 0; i < numKeys; ++i) {
      __m128i K = keys[i].rd_key[r];
      for (size_t j = 0; j < numEncs; ++j) {
        *blks = _mm_aesenc_si128(*blks, K);
        ++blks;
      }
    }
  }

  blks = first;
  for (size_t i = 0; i < numKeys; ++i) {
    __m128i K = keys[i].rd_key[10];
    for (size_t j = 0; j < numEncs; ++j) {
      *blks = _mm_aesenclast_si128(*blks, K);
      ++blks;
    }
  }
}
#elif __aarch64__
template <int numKeys, int numEncs>
static inline void ParaEnc(__m128i *_blks, const AES_KEY *keys) {
  uint8x16_t *first = (uint8x16_t *)(_blks);

  for (unsigned int r = 0; r < 9; ++r) {
    auto blks = first;
    for (size_t i = 0; i < numKeys; ++i) {
      uint8x16_t K = vreinterpretq_u8_m128i(keys[i].rd_key[r]);
      for (size_t j = 0; j < numEncs; ++j, ++blks)
        *blks = vaesmcq_u8(vaeseq_u8(*blks, K));
    }
  }

  auto blks = first;
  for (size_t i = 0; i < numKeys; ++i) {
    uint8x16_t K = vreinterpretq_u8_m128i(keys[i].rd_key[9]);
    uint8x16_t K2 = vreinterpretq_u8_m128i(keys[i].rd_key[10]);
    for (size_t j = 0; j < numEncs; ++j, ++blks)
      *blks = vaeseq_u8(*blks, K) ^ K2;
  }
}
#endif

/*
 * With numKeys keys, use each key to encrypt numEncs blocks.
 */
#ifdef __x86_64__
template <int numKeys>
static inline void ParaEnc(__m128i *blks, const AES_KEY *keys,
                           size_t num_encs) {
  __m128i *first = blks;
  for (size_t i = 0; i < numKeys; ++i) {
    __m128i K = keys[i].rd_key[0];
    for (size_t j = 0; j < num_encs; ++j) {
      *blks = *blks ^ K;
      ++blks;
    }
  }
  for (unsigned int r = 1; r < 10; ++r) {
    blks = first;
    for (size_t i = 0; i < numKeys; ++i) {
      __m128i K = keys[i].rd_key[r];
      for (size_t j = 0; j < num_encs; ++j) {
        *blks = _mm_aesenc_si128(*blks, K);
        ++blks;
      }
    }
  }
  blks = first;
  for (size_t i = 0; i < numKeys; ++i) {
    __m128i K = keys[i].rd_key[10];
    for (size_t j = 0; j < num_encs; ++j) {
      *blks = _mm_aesenclast_si128(*blks, K);
      ++blks;
    }
  }
}
#elif __aarch64__
template <int numKeys>
static inline void ParaEnc(__m128i *_blks, const AES_KEY *keys,
                           size_t num_encs) {
  uint8x16_t *first = (uint8x16_t *)(_blks);
  for (unsigned int r = 0; r < 9; ++r) {
    auto blks = first;
    for (size_t i = 0; i < numKeys; ++i) {
      uint8x16_t K = vreinterpretq_u8_m128i(keys[i].rd_key[r]);
      for (size_t j = 0; j < num_encs; ++j, ++blks)
        *blks = vaesmcq_u8(vaeseq_u8(*blks, K));
    }
  }
  auto blks = first;
  for (size_t i = 0; i < numKeys; ++i) {
    uint8x16_t K = vreinterpretq_u8_m128i(keys[i].rd_key[9]);
    uint8x16_t K2 = vreinterpretq_u8_m128i(keys[i].rd_key[10]);
    for (size_t j = 0; j < num_encs; ++j, ++blks)
      *blks = vaeseq_u8(*blks, K) ^ K2;
  }
}
#endif

///////////////////////////////////////////////////////////////////
//                      uint128_t support                        //
///////////////////////////////////////////////////////////////////
template <int NumKeys>
static inline void AES_opt_key_schedule(uint128_t *user_key, AES_KEY *keys) {
  auto *tmp = reinterpret_cast<__m128i *>(user_key);
  AES_opt_key_schedule<NumKeys>(tmp, keys);
}

template <int numKeys, int numEncs>
static inline void ParaEnc(uint128_t *blks, const AES_KEY *keys) {
  auto *tmp = reinterpret_cast<__m128i *>(blks);
  ParaEnc<numKeys, numEncs>(tmp, keys);
}

template <int numKeys>
static inline void ParaEnc(uint128_t *blks, const AES_KEY *keys,
                           size_t num_encs) {
  auto *tmp = reinterpret_cast<__m128i *>(blks);
  ParaEnc<numKeys>(tmp, keys, num_encs);
}

}  // namespace yacl::crypto
