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

#include "yacl/math/mpint/tommath_ext_types.h"

#include <climits>

#include "yacl/math/mpint/mp_int_enforce.h"

extern "C" {
#include "libtommath/tommath_private.h"
}

// Following macros are copied from tommath_private.h
#define MP_MIN(x, y) (((x) < (y)) ? (x) : (y))
#define MP_MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MP_SIZEOF_BITS(type) ((size_t)CHAR_BIT * sizeof(type))

void mpx_init(mp_int *a) {
  a->dp = nullptr;
  a->used = 0;
  a->alloc = 0;
  a->sign = MP_ZPOS;
}

void mpx_reserve(mp_int *a, size_t n_digits) {
  if (a->dp == nullptr) {
    a->dp = static_cast<mp_digit *>(MP_CALLOC(n_digits, sizeof(mp_digit)));
    YACL_ENFORCE(a->dp != nullptr);
    a->alloc = n_digits;
    return;
  }

  MPINT_ENFORCE_OK(mp_grow(a, n_digits));
}

#define MPX_INIT_INT(name, set, type) \
  mp_err name(mp_int *a, type b) {    \
    mpx_init(a);                      \
    set(a, b);                        \
    return MP_OKAY;                   \
  }

#define MPX_SET_UNSIGNED(name, type)                                     \
  void name(mp_int *a, type b) {                                         \
    MPINT_ENFORCE_OK(mp_grow(a, MP_BYTES_TO_DIGITS(sizeof(type))));      \
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
    s_mp_zero_digs(a->dp + a->used, a->alloc - a->used);                 \
  }

#define MPX_SET_SIGNED(name, uname, type, utype) \
  void name(mp_int *a, type b) {                 \
    uname(a, (b < 0) ? -(utype)b : (utype)b);    \
    if (b < 0) {                                 \
      a->sign = MP_NEG;                          \
    }                                            \
  }

#define MPX_GET_MAG(name, type)                                                \
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

#define MPX_GET_SIGNED(name, mag, type, utype)           \
  type name(const mp_int *a) {                           \
    utype res = mag(a);                                  \
    return (a->sign == MP_NEG) ? -(type)res : (type)res; \
  }

// define int8 related functions.
MPX_SET_UNSIGNED(mpx_set_u8, uint8_t)
MPX_SET_SIGNED(mpx_set_i8, mpx_set_u8, int8_t, uint8_t)
MPX_GET_MAG(mpx_get_mag_u8, uint8_t)
MPX_GET_SIGNED(mpx_get_i8, mpx_get_mag_u8, int8_t, uint8_t)

// define int16 related functions.
MPX_SET_UNSIGNED(mpx_set_u16, uint16_t)
MPX_SET_SIGNED(mpx_set_i16, mpx_set_u16, int16_t, uint16_t)
MPX_GET_MAG(mpx_get_mag_u16, uint16_t)
MPX_GET_SIGNED(mpx_get_i16, mpx_get_mag_u16, int16_t, uint16_t)

// define int32 related functions.
MPX_SET_UNSIGNED(mpx_set_u32, uint32_t)
MPX_SET_SIGNED(mpx_set_i32, mpx_set_u32, int32_t, uint32_t)
MPX_GET_MAG(mpx_get_mag_u32, uint32_t)
MPX_GET_SIGNED(mpx_get_i32, mpx_get_mag_u32, int32_t, uint32_t)

// define int64 related functions.
MPX_SET_UNSIGNED(mpx_set_u64, uint64_t)
MPX_SET_SIGNED(mpx_set_i64, mpx_set_u64, int64_t, uint64_t)
MPX_GET_MAG(mpx_get_mag_u64, uint64_t)
MPX_GET_SIGNED(mpx_get_i64, mpx_get_mag_u64, int64_t, uint64_t)

// define int128 related functions.
MPX_INIT_INT(mpx_init_i128, mpx_set_i128, int128_t)
MPX_INIT_INT(mpx_init_u128, mpx_set_u128, uint128_t)
MPX_SET_UNSIGNED(mpx_set_u128, uint128_t)
MPX_SET_SIGNED(mpx_set_i128, mpx_set_u128, int128_t, uint128_t)
MPX_GET_MAG(mpx_get_mag_u128, uint128_t)
MPX_GET_SIGNED(mpx_get_i128, mpx_get_mag_u128, int128_t, uint128_t)
