// Copyright 2023 Ant Group Co., Ltd.
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

#include <array>
#include <vector>

#include "absl/types/span.h"

#include "yacl/base/exception.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/tools/random_permutation.h"

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

constexpr uint32_t kLcBatchSize = 128;  // linear code batch size

// Linear code interface in F2k
class LinearCodeInterface {
 public:
  LinearCodeInterface(const LinearCodeInterface &) = delete;
  LinearCodeInterface &operator=(const LinearCodeInterface &) = delete;
  LinearCodeInterface() = default;
  virtual ~LinearCodeInterface() = default;

  // Get the dimention / length
  virtual uint32_t GetDimention() const = 0;
  virtual uint32_t GetLength() const = 0;

  // (maybe randomly) Generate generator matrix
  // virtual void GenGenerator() const = 0;
};

// Implementation of d-local linear code in F2k, for more details, see original
// paper: https://arxiv.org/pdf/2102.00597.pdf
//
// For parameter choices, see analysis in https://eprint.iacr.org/2019/273.pdf
// Page 20, Table 1.
//
// Implementation mostly from:
// https://github.com/emp-toolkit/emp-ot/blob/master/emp-ot/ferret/lpn_f2.h
//
// For more details about SSE2, see:
// https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html

template <size_t d = 10>
class LocalLinearCode : LinearCodeInterface {
 public:
  // constructor
  LocalLinearCode(uint128_t seed, size_t n, size_t k)
      : n_(n), k_(k), rp_(SymmetricCrypto::CryptoType::AES128_ECB, seed) {
    // YACL_ENFORCE(n % kLcBatchSize == 0);
    mask_ = 1;
    while (mask_ < k) {
      mask_ <<= 1;
      mask_ = mask_ | 0x1;
    }

    uint64_t mask64 = ((uint64_t)mask_ << 32 | mask_);
    extend_mask_ = MakeUint128(mask64, mask64);

    uint64_t k64 = ((uint64_t)k_ << 32 | k_);
    extend_k_ = MakeUint128(k64, k64);

    uint64_t cmp64 = ((uint64_t)(k_ - 1) << 32 | (k_ - 1));
    extend_cmp_ = MakeUint128(cmp64, cmp64);
  }

  // override functions
  uint32_t GetDimention() const override { return k_; }
  uint32_t GetLength() const override { return n_; }

  // Encode a message (input) into a codeword (output)
  void Encode(absl::Span<const uint128_t> in, absl::Span<uint128_t> out) {
    YACL_ENFORCE_EQ(in.size(), k_);
    YACL_ENFORCE_EQ(out.size(), n_);

    // const uint32_t batch_num = (n_ + kLcBatchSize - 1) / kLcBatchSize;

    constexpr uint32_t tmp_size = kLcBatchSize * d / 4;
    alignas(16) std::array<uint128_t, tmp_size> tmp;

    auto mask_tmp =
        _mm_loadu_si128((reinterpret_cast<__m128i *>(&extend_mask_)));
    auto k_tmp = _mm_loadu_si128((reinterpret_cast<__m128i *>(&extend_k_)));
    auto cmp_tmp = _mm_loadu_si128((reinterpret_cast<__m128i *>(&extend_cmp_)));

    for (uint32_t i = 0; i < n_; i += kLcBatchSize) {
      const uint32_t limit = std::min(kLcBatchSize, n_ - i);
      const uint32_t block_num = limit * d / 4;

      for (uint32_t j = 0; j < block_num; ++j) {
        _mm_store_si128(reinterpret_cast<__m128i *>(&tmp[j]),
                        _mm_set_epi32(i, 0, j, 0));
      }

      rp_.GenInplace(absl::MakeSpan(reinterpret_cast<uint128_t *>(tmp.data()),
                                    block_num));  // kBatchSize * 10 / 4

      // SIMD
      for (uint32_t j = 0; j < block_num; ++j) {
        auto idx128 = _mm_load_si128(reinterpret_cast<__m128i *>(&tmp[j]));
        idx128 = _mm_and_si128(idx128, mask_tmp);
        // compare idx128 and cmp_tmp
        // return 0xFFFF if true, return 0x0000 otherwise.
        auto sub = _mm_cmpgt_epi32(idx128, cmp_tmp);
        // return k_tmp if idx128 greater than or equal to k
        // return 0x0000 otherwise
        sub = _mm_and_si128(sub, k_tmp);
        idx128 = _mm_sub_epi32(idx128, sub);
        _mm_store_si128(reinterpret_cast<__m128i *>(&tmp[j]), idx128);
      }

      auto *ptr = reinterpret_cast<uint32_t *>(tmp.data());
      for (uint32_t j = 0; j < limit; ++j) {
        auto tmp = _mm_loadu_si128(reinterpret_cast<__m128i *>(&out[i + j]));
        for (uint32_t k = 0; k < d; ++k, ++ptr) {
          tmp = _mm_xor_si128(tmp, reinterpret_cast<__m128i>(in[*ptr]));
        }
        _mm_storeu_si128(reinterpret_cast<__m128i *>(&out[i + j]), tmp);
      }
    }
  }

 private:
  uint32_t n_;  // num
  uint32_t k_;  // dimention
  RandomPerm rp_;
  uint32_t mask_;
  uint128_t extend_mask_;
  uint128_t extend_k_;
  uint128_t extend_cmp_;
};

}  // namespace yacl::crypto
