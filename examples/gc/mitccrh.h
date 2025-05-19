// Copyright 2024 Ant Group Co., Ltd.
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

#pragma once

#include "utils.h"

#include "yacl/crypto/aes/aes_opt.h"

/*
 * [REF] Implementation of "Better Concrete Security for Half-Gates Garbling (in
 * the Multi-Instance Setting)" https://eprint.iacr.org/2019/1168.pdf
 */

using block = __uint128_t;

inline uint128_t Sigma(uint128_t x) {
  auto _x = _mm_loadu_si128(reinterpret_cast<__m128i*>(&x));
  auto exchange = _mm_shuffle_epi32(_x, 0b01001110);
  auto left = _mm_unpackhi_epi64(_x, _mm_setzero_si128());
  return reinterpret_cast<uint128_t>(_mm_xor_si128(exchange, left));
}

template <int BatchSize = 8>
class MITCCRH {
 public:
  yacl::crypto::AES_KEY scheduled_key[BatchSize];
  block keys[BatchSize];
  int key_used = BatchSize;
  block start_point;
  uint64_t gid = 0;

  void setS(block sin) { this->start_point = sin; }

  void renew_ks(uint64_t gid) {
    this->gid = gid;
    renew_ks();
  }

  void renew_ks() {
    for (int i = 0; i < BatchSize; ++i)
      keys[i] = start_point ^ yacl::MakeUint128(gid++, (uint64_t)0);
    yacl::crypto::AES_opt_key_schedule<BatchSize>(keys, scheduled_key);
    key_used = 0;
  }

  template <int K, int H>
  void hash_cir(block* blks) {
    for (int i = 0; i < K * H; ++i) blks[i] = Sigma(blks[i]);
    hash<K, H>(blks);
  }

  template <int K, int H>
  void hash(block* blks, bool used = false) {
    assert(K <= BatchSize);
    assert(BatchSize % K == 0);
    if (key_used == BatchSize) renew_ks();

    block tmp[K * H];
    for (int i = 0; i < K * H; ++i) tmp[i] = blks[i];

    yacl::crypto::ParaEnc<K, H>(tmp, scheduled_key + key_used);
    if (used) key_used += K;

    for (int i = 0; i < K * H; ++i) blks[i] = blks[i] ^ tmp[i];
  }
};
