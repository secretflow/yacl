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

#include "yacl/crypto/base/mpint/type_traits.h"

namespace yacl::crypto {

// Reference: https://eprint.iacr.org/2003/186.pdf
// libtommath style
void mp_ext_safe_prime_rand(mp_int *out, int t, int size);

void mp_ext_rand_bits(mp_int *out, int64_t bits);

// Convert num to bytes and output to buf
void mp_ext_to_bytes(const mp_int &num, unsigned char *buf, int64_t byte_len,
                     Endian endian = Endian::native);

// returns the number of bits in an int
// Faster than tommath's native mp_count_bits() method
int mp_ext_count_bits_fast(const mp_int &a);

size_t mp_ext_serialize_size(const mp_int &num);
void mp_ext_serialize(const mp_int &num, uint8_t *buf, size_t buf_len);
void mp_ext_deserialize(mp_int *num, const uint8_t *buf, size_t buf_len);

}  // namespace yacl::crypto
