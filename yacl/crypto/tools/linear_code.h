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
#include <cstdint>
#include <cstring>
#include <future>
#include <vector>

#include "yacl/base/byte_container_view.h"
#include "yacl/base/exception.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/tools/random_permutation.h"
#include "yacl/utils/thread_pool.h"

namespace yacl::crypto {

constexpr uint32_t kLcBatchSize = 256;  // linear code batch size

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
  }

  // override functions
  uint32_t GetDimention() const override { return k_; }
  uint32_t GetLength() const override { return n_; }

  // Encode a message (input) into a codeword (output)
  void Encode(absl::Span<const uint128_t> in, absl::Span<uint128_t> out) {
    YACL_ENFORCE_EQ(in.size(), k_);
    YACL_ENFORCE_EQ(out.size(), n_);

    const uint32_t batch_num = (n_ + kLcBatchSize - 1) / kLcBatchSize;

    for (uint32_t i = 0; i < batch_num; ++i) {
      const uint32_t limit = std::min(kLcBatchSize, n_ - i * kLcBatchSize);
      const uint32_t block_num = limit * d / 4;

      std::vector<uint128_t> tmp(block_num);
      for (uint32_t j = 0; j < block_num; ++j) {
        tmp[j] = MakeUint128(i, j);
      }

      rp_.GenInplace(absl::MakeSpan(tmp));  // kBatchSize * 10 / 4

      auto *ptr = reinterpret_cast<uint32_t *>(tmp.data());
      for (uint32_t j = 0; j < limit; ++j) {
        for (uint32_t k = 0; k < d; ++k, ++ptr) {
          uint32_t index = (*ptr) & mask_;

          index = index >= k_ ? index - k_ : index;
          out[i + j] = out[i + j] ^ in[index];
        }
      }
    }
  }

 private:
  uint32_t n_;  // num
  uint32_t k_;  // dimention
  RandomPerm rp_;
  uint32_t mask_;
};

}  // namespace yacl::crypto
