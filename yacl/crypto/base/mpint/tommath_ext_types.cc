// Copyright 2022 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "yacl/crypto/base/mpint/tommath_ext_types.h"

#include <cstring>  // memset

// Following macros are copied from tommath_private.h
#define MP_MIN(x, y) (((x) < (y)) ? (x) : (y))
#define MP_MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MP_SIZEOF_BITS(type) ((size_t)CHAR_BIT * sizeof(type))
#define MP_ZERO_DIGITS(mem, digits)                     \
  do {                                                  \
    int zd_ = (digits);                                 \
    if (zd_ > 0) {                                      \
      memset((mem), 0, sizeof(mp_digit) * (size_t)zd_); \
    }                                                   \
  } while (0)

#define MP_INIT_INT(name, set, type)     \
  mp_err name(mp_int *a, type b) {       \
    mp_err err;                          \
    if ((err = mp_init(a)) != MP_OKAY) { \
      return err;                        \
    }                                    \
    set(a, b);                           \
    return MP_OKAY;                      \
  }

#define MP_SET_UNSIGNED(name, type)                                      \
  void name(mp_int *a, type b) {                                         \
    int i = 0;                                                           \
    while (b != 0u) {                                                    \
      a->dp[i++] = ((mp_digit)b & MP_MASK);                              \
      if (MP_SIZEOF_BITS(type) <= MP_DIGIT_BIT) {                        \
        break;                                                           \
      }                                                                  \
      b >>= ((MP_SIZEOF_BITS(type) <= MP_DIGIT_BIT) ? 0 : MP_DIGIT_BIT); \
    }                                                                    \
    a->used = i;                                                         \
    a->sign = MP_ZPOS;                                                   \
    MP_ZERO_DIGITS(a->dp + a->used, a->alloc - a->used);                 \
  }

#define MP_SET_SIGNED(name, uname, type, utype) \
  void name(mp_int *a, type b) {                \
    uname(a, (b < 0) ? -(utype)b : (utype)b);   \
    if (b < 0) {                                \
      a->sign = MP_NEG;                         \
    }                                           \
  }

#define MP_GET_MAG(name, type)                                                 \
  type name(const mp_int *a) {                                                 \
    unsigned i = MP_MIN(                                                       \
        (unsigned)a->used,                                                     \
        (unsigned)((MP_SIZEOF_BITS(type) + MP_DIGIT_BIT - 1) / MP_DIGIT_BIT)); \
    type res = 0u;                                                             \
    while (i-- > 0u) {                                                         \
      res <<= ((MP_SIZEOF_BITS(type) <= MP_DIGIT_BIT) ? 0 : MP_DIGIT_BIT);     \
      res |= (type)a->dp[i];                                                   \
      if (MP_SIZEOF_BITS(type) <= MP_DIGIT_BIT) {                              \
        break;                                                                 \
      }                                                                        \
    }                                                                          \
    return res;                                                                \
  }

#define MP_GET_SIGNED(name, mag, type, utype)            \
  type name(const mp_int *a) {                           \
    utype res = mag(a);                                  \
    return (a->sign == MP_NEG) ? -(type)res : (type)res; \
  }

// define int8 related functions.
MP_SET_UNSIGNED(mp_set_u8, uint8_t)
MP_SET_SIGNED(mp_set_i8, mp_set_u8, int8_t, uint8_t)
MP_GET_MAG(mp_get_mag_u8, uint8_t)
MP_GET_SIGNED(mp_get_i8, mp_get_mag_u8, int8_t, uint8_t)

// define int16 related functions.
MP_SET_UNSIGNED(mp_set_u16, uint16_t)
MP_SET_SIGNED(mp_set_i16, mp_set_u16, int16_t, uint16_t)
MP_GET_MAG(mp_get_mag_u16, uint16_t)
MP_GET_SIGNED(mp_get_i16, mp_get_mag_u16, int16_t, uint16_t)

// define int128 related functions.
MP_INIT_INT(mp_init_i128, mp_set_i128, int128_t)
MP_INIT_INT(mp_init_u128, mp_set_u128, uint128_t)
MP_SET_UNSIGNED(mp_set_u128, uint128_t)
MP_SET_SIGNED(mp_set_i128, mp_set_u128, int128_t, uint128_t)
MP_GET_MAG(mp_get_mag_u128, uint128_t)
MP_GET_SIGNED(mp_get_i128, mp_get_mag_u128, int128_t, uint128_t)
