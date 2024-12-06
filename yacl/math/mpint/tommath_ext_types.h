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

#pragma once

#include "libtommath/tommath.h"

#include "yacl/base/int128.h"

#define MP_BITS_TO_DIGITS(bits) ((bits) + MP_DIGIT_BIT - 1) / MP_DIGIT_BIT
#define MP_BYTES_TO_DIGITS(bytes) MP_BITS_TO_DIGITS((bytes) * CHAR_BIT)

void mpx_init(mp_int *a);
void mpx_reserve(mp_int *a, size_t n_digits);

// define int8 related functions.
void mpx_set_u8(mp_int *a, uint8_t b);
void mpx_set_i8(mp_int *a, int8_t b);
uint8_t mpx_get_mag_u8(const mp_int *a);
int8_t mpx_get_i8(const mp_int *a);
#define mpx_get_u8(a) ((uint8_t)mpx_get_i8(a))

// define int16 related functions.
void mpx_set_u16(mp_int *a, uint16_t b);
void mpx_set_i16(mp_int *a, int16_t b);
uint16_t mpx_get_mag_u16(const mp_int *a);
int16_t mpx_get_i16(const mp_int *a);
#define mpx_get_u16(a) ((uint16_t)mpx_get_i16(a))

// define int32 related functions.
void mpx_set_u32(mp_int *a, uint32_t b);
void mpx_set_i32(mp_int *a, int32_t b);
uint32_t mpx_get_mag_u32(const mp_int *a);
int32_t mpx_get_i32(const mp_int *a);
#define mpx_get_u32(a) ((uint32_t)mpx_get_i32(a))

// define int64 related functions.
void mpx_set_u64(mp_int *a, uint64_t b);
void mpx_set_i64(mp_int *a, int64_t b);
uint64_t mpx_get_mag_u64(const mp_int *a);
int64_t mpx_get_i64(const mp_int *a);
#define mpx_get_u64(a) ((uint64_t)mpx_get_i64(a))

// define int128 related functions.
mp_err mpx_init_i128(mp_int *a, int128_t b) MP_WUR;
mp_err mpx_init_u128(mp_int *a, uint128_t b) MP_WUR;

void mpx_set_u128(mp_int *a, uint128_t b);
void mpx_set_i128(mp_int *a, int128_t b);
uint128_t mpx_get_mag_u128(const mp_int *a);
int128_t mpx_get_i128(const mp_int *a);
#define mpx_get_u128(a) ((uint128_t)mpx_get_i128(a))
