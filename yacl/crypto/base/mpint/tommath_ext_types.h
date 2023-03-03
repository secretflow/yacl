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

#include "tommath.h"

#include "yacl/base/int128.h"

// define int8 related functions.
void mp_set_u8(mp_int *a, uint8_t b);
void mp_set_i8(mp_int *a, int8_t b);

uint8_t mp_get_mag_u8(const mp_int *a);
int8_t mp_get_i8(const mp_int *a);
#define mp_get_u8(a) ((uint8_t)mp_get_i8(a))

// define int16 related functions.
void mp_set_u16(mp_int *a, uint16_t b);
void mp_set_i16(mp_int *a, int16_t b);

uint16_t mp_get_mag_u16(const mp_int *a);
int16_t mp_get_i16(const mp_int *a);
#define mp_get_u16(a) ((uint16_t)mp_get_i16(a))

// define int128 related functions.
mp_err mp_init_i128(mp_int *a, int128_t b) MP_WUR;
mp_err mp_init_u128(mp_int *a, uint128_t b) MP_WUR;

void mp_set_u128(mp_int *a, uint128_t b);
void mp_set_i128(mp_int *a, int128_t b);

uint128_t mp_get_mag_u128(const mp_int *a);
int128_t mp_get_i128(const mp_int *a);
#define mp_get_u128(a) ((uint128_t)mp_get_i128(a))
