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

#include <algorithm>
#include <array>

#include "absl/types/span.h"

#include "yacl/base/exception.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/tools/rp.h"
#include "yacl/kernel/code/code_interface.h"
#include "yacl/math/gadget.h"

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

constexpr uint32_t kLcBatchSize = 1024;  // linear code batch size

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
class LocalLinearCode : public LinearCodeInterface {
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

    uint64_t mask64 = (static_cast<uint64_t>(mask_) << 32 | mask_);
    extend_mask_ = MakeUint128(mask64, mask64);

    uint64_t k64 = (static_cast<uint64_t>(k_) << 32 | k_);
    extend_k_ = MakeUint128(k64, k64);

    uint64_t cmp64 = (static_cast<uint64_t>(k_ - 1) << 32 | (k_ - 1));
    extend_cmp_ = MakeUint128(cmp64, cmp64);
  }

  // override functions
  uint32_t GetDimention() const override { return k_; }
  uint32_t GetLength() const override { return n_; }

  // Encode a message (input) into a codeword (output)
  void Encode(absl::Span<const uint128_t> in, absl::Span<uint128_t> out) const {
    YACL_ENFORCE_EQ(in.size(), k_);
    // YACL_ENFORCE_EQ(out.size(), n_);

    constexpr uint32_t tmp_size = math::DivCeil(kLcBatchSize * d, 4);
    alignas(16) std::array<uint128_t, tmp_size> tmp;

    for (uint32_t i = 0; i < out.size(); i += kLcBatchSize) {
      const uint32_t limit =
          std::min(kLcBatchSize, static_cast<uint32_t>(out.size()) - i);
      const uint32_t block_num = math::DivCeil(limit * d, 4);

      // generate non-zero indexes
      GenIndexes(i, block_num, absl::MakeSpan(tmp));

      const auto *ptr = reinterpret_cast<const uint32_t *>(tmp.data());
      for (uint32_t j = 0; j < limit; ++j) {
        auto val = _mm_loadu_si128(reinterpret_cast<__m128i *>(&out[i + j]));
        for (uint32_t k = 0; k < d; ++k, ++ptr) {
          val = _mm_xor_si128(val, reinterpret_cast<__m128i>(in[*ptr]));
        }
        _mm_storeu_si128(reinterpret_cast<__m128i *>(&out[i + j]), val);
      }
    }
  }

  void Encode2(absl::Span<const uint128_t> in0, absl::Span<uint128_t> out0,
               absl::Span<const uint128_t> in1,
               absl::Span<uint128_t> out1) const {
    YACL_ENFORCE_EQ(in0.size(), k_);
    YACL_ENFORCE_EQ(in1.size(), k_);

    auto size = std::min(out0.size(), out1.size());
    // YACL_ENFORCE_EQ(out.size(), n_);

    constexpr uint32_t tmp_size = math::DivCeil(kLcBatchSize * d, 4);
    alignas(16) std::array<uint128_t, tmp_size> tmp;

    for (uint32_t i = 0; i < size; i += kLcBatchSize) {
      const uint32_t limit =
          std::min(kLcBatchSize, static_cast<uint32_t>(size) - i);
      const uint32_t block_num = math::DivCeil(limit * d, 4);

      GenIndexes(i, block_num, absl::MakeSpan(tmp));

      const auto *ptr = reinterpret_cast<const uint32_t *>(tmp.data());
      for (uint32_t j = 0; j < limit; ++j) {
        auto val0 = _mm_loadu_si128(reinterpret_cast<__m128i *>(&out0[i + j]));
        auto val1 = _mm_loadu_si128(reinterpret_cast<__m128i *>(&out1[i + j]));
        for (uint32_t k = 0; k < d; ++k, ++ptr) {
          val0 = _mm_xor_si128(val0, reinterpret_cast<__m128i>(in0[*ptr]));
          val1 = _mm_xor_si128(val1, reinterpret_cast<__m128i>(in1[*ptr]));
        }
        _mm_storeu_si128(reinterpret_cast<__m128i *>(&out0[i + j]), val0);
        _mm_storeu_si128(reinterpret_cast<__m128i *>(&out1[i + j]), val1);
      }
    }
  }

  // Encode a message (input) into a codeword (output)
  void Encode(absl::Span<const uint64_t> in, absl::Span<uint64_t> out) const {
    YACL_ENFORCE_EQ(in.size(), k_);
    // YACL_ENFORCE_EQ(out.size(), n_);

    constexpr uint32_t tmp_size = math::DivCeil(kLcBatchSize * d, 4);
    alignas(16) std::array<uint128_t, tmp_size> tmp;

    for (uint32_t i = 0; i < out.size(); i += kLcBatchSize) {
      const uint32_t limit =
          std::min(kLcBatchSize, static_cast<uint32_t>(out.size()) - i);
      const uint32_t block_num = math::DivCeil(limit * d, 4);

      GenIndexes(i, block_num, absl::MakeSpan(tmp));

      const auto *ptr = reinterpret_cast<const uint32_t *>(tmp.data());
      for (uint32_t j = 0; j < limit; ++j) {
        auto val = out[i + j];
        for (uint32_t k = 0; k < d; ++k, ++ptr) {
          val ^= in[*ptr];
        }
        out[i + j] = val;
      }
    }
  }

  void Encode2(absl::Span<const uint64_t> in0, absl::Span<uint64_t> out0,
               absl::Span<const uint64_t> in1,
               absl::Span<uint64_t> out1) const {
    YACL_ENFORCE_EQ(in0.size(), k_);
    YACL_ENFORCE_EQ(in1.size(), k_);

    auto size = std::min(out0.size(), out1.size());
    // YACL_ENFORCE_EQ(out.size(), n_);

    constexpr uint32_t tmp_size = math::DivCeil(kLcBatchSize * d, 4);
    alignas(16) std::array<uint128_t, tmp_size> tmp;

    for (uint32_t i = 0; i < size; i += kLcBatchSize) {
      const uint32_t limit =
          std::min(kLcBatchSize, static_cast<uint32_t>(size) - i);
      const uint32_t block_num = math::DivCeil(limit * d, 4);

      GenIndexes(i, block_num, absl::MakeSpan(tmp));

      const auto *ptr = reinterpret_cast<const uint32_t *>(tmp.data());
      for (uint32_t j = 0; j < limit; ++j) {
        auto val0 = out0[i + j];
        auto val1 = out1[i + j];
        for (uint32_t k = 0; k < d; ++k, ++ptr) {
          val0 ^= in0[*ptr];
          val1 ^= in1[*ptr];
        }
        out0[i + j] = val0;
        out1[i + j] = val1;
      }
    }
  }

  void Encode2(absl::Span<const uint64_t> in0, absl::Span<uint64_t> out0,
               absl::Span<const uint128_t> in1,
               absl::Span<uint128_t> out1) const {
    YACL_ENFORCE_EQ(in0.size(), k_);
    YACL_ENFORCE_EQ(in1.size(), k_);

    auto size = std::min(out0.size(), out1.size());
    // YACL_ENFORCE_EQ(out.size(), n_);

    constexpr uint32_t tmp_size = math::DivCeil(kLcBatchSize * d, 4);
    alignas(16) std::array<uint128_t, tmp_size> tmp;

    for (uint32_t i = 0; i < size; i += kLcBatchSize) {
      const uint32_t limit =
          std::min(kLcBatchSize, static_cast<uint32_t>(size) - i);
      const uint32_t block_num = math::DivCeil(limit * d, 4);

      GenIndexes(i, block_num, absl::MakeSpan(tmp));

      const auto *ptr = reinterpret_cast<const uint32_t *>(tmp.data());
      for (uint32_t j = 0; j < limit; ++j) {
        auto val0 = out0[i + j];
        auto val1 = _mm_loadu_si128(reinterpret_cast<__m128i *>(&out1[i + j]));
        for (uint32_t k = 0; k < d; ++k, ++ptr) {
          val0 ^= in0[*ptr];
          val1 = _mm_xor_si128(val1, reinterpret_cast<__m128i>(in1[*ptr]));
        }
        out0[i + j] = val0;
        _mm_storeu_si128(reinterpret_cast<__m128i *>(&out1[i + j]), val1);
      }
    }
  }

 private:
  uint32_t n_;  // num
  uint32_t k_;  // dimention
  RP rp_;
  uint32_t mask_;
  uint128_t extend_mask_;
  uint128_t extend_k_;
  uint128_t extend_cmp_;

  // Generate non-zero indexes
  inline void GenIndexes(uint32_t i, uint32_t block_num,
                         absl::Span<uint128_t> tmp) const {
    for (uint32_t j = 0; j < block_num; ++j) {
      _mm_store_si128(reinterpret_cast<__m128i *>(&tmp[j]),
                      _mm_set_epi32(i, 0, j, 0));
    }
    // Generate random indexes by Random Permutation
    rp_.GenInplace(absl::MakeSpan(reinterpret_cast<uint128_t *>(tmp.data()),
                                  block_num));  // kBatchSize * 10 / 4

    auto mask_tmp =
        _mm_loadu_si128((reinterpret_cast<const __m128i *>(&extend_mask_)));
    auto k_tmp =
        _mm_loadu_si128((reinterpret_cast<const __m128i *>(&extend_k_)));
    auto cmp_tmp =
        _mm_loadu_si128((reinterpret_cast<const __m128i *>(&extend_cmp_)));

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
  }
};

}  // namespace yacl::crypto
