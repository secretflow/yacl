// Copyright 2022 Ant Group Co., Ltd.
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

#include "yacl/crypto/rand/rand.h"

#include <limits>
#include <memory>

#include "yacl/base/byte_container_view.h"
#include "yacl/base/dynamic_bitset.h"
#include "yacl/crypto/ossl-provider/helper.h"
#include "yacl/crypto/rand/entropy_source/entropy_source.h"
#include "yacl/math/gadget.h"

namespace yacl::crypto {

// --------------------
// Core Implementations
// --------------------
RandCtx::RandCtx(SecParam::C c, bool use_yacl_es) : c_(c) {
  ctr_drbg_ = DrbgFactory::Instance().Create(
      "ctr-drbg", ArgUseYaclEs = use_yacl_es, ArgSecParamC = c_);
  hash_drbg_ = DrbgFactory::Instance().Create(
      "hash-drbg", ArgUseYaclEs = use_yacl_es, ArgSecParamC = c_);
}

void RandCtx::Fill(char *buf, size_t len, bool use_fast_mode) const {
  YACL_ENFORCE(len <= std::numeric_limits<int>::max());
  if (use_fast_mode) {
    hash_drbg_->Fill(buf, len);
  } else {
    ctr_drbg_->Fill(buf, len);
  }
}

// ---------------------
// Other Implementations
// ---------------------
uint64_t RandU64(const RandCtx &ctx, bool use_fast_mode) {
  uint64_t rand64 = 0;
  FillRand(ctx, reinterpret_cast<char *>(&rand64), sizeof(uint64_t),
           use_fast_mode);
  return rand64;
}

uint128_t RandU128(const RandCtx &ctx, bool use_fast_mode) {
  uint128_t rand128 = 0;
  FillRand(ctx, reinterpret_cast<char *>(&rand128), sizeof(uint128_t),
           use_fast_mode);
  return rand128;
}

template <>
std::vector<bool> RandBits<std::vector<bool>>(uint64_t len,
                                              bool use_fast_mode) {
  std::vector<bool> out(len, false);
  const unsigned stride = sizeof(unsigned) * 8;

  // generate randomness
  auto rand_buf = RandVec<unsigned>(len, use_fast_mode);

  // for each byte
  for (uint64_t i = 0; i < len; i += stride) {
    unsigned size = std::min(stride, static_cast<unsigned>(len - i));
    for (unsigned j = 0; j < size; ++j) {
      out[i + j] = (rand_buf[i] & (1 << j)) != 0;
    }
  }
  return out;
}

#define IMPL_RANDBIT_DYNAMIC_BIT_TYPE(T)                                      \
  template <>                                                                 \
  dynamic_bitset<T> RandBits<dynamic_bitset<T>>(uint64_t len,                 \
                                                bool use_fast_mode) {         \
    dynamic_bitset<T> out(len);                                               \
    size_t byte_len = math::DivCeil(len, 8);                                  \
                                                                              \
    /* generate randomness */                                                 \
    auto rand_buf = RandBytes(byte_len, use_fast_mode);                       \
                                                                              \
    /* for each byte */                                                       \
    for (uint64_t i = 0; i < len; i += 8) {                                   \
      uint64_t size =                                                         \
          std::min(static_cast<uint64_t>(8), static_cast<uint64_t>(len - i)); \
      uint64_t offset = i >> 3;                                               \
      for (unsigned j = 0; j < size; ++j) {                                   \
        out[i + j] = (rand_buf[offset] & (1 << j)) != 0;                      \
      }                                                                       \
    }                                                                         \
    return out;                                                               \
  }

IMPL_RANDBIT_DYNAMIC_BIT_TYPE(uint128_t);
IMPL_RANDBIT_DYNAMIC_BIT_TYPE(uint64_t);
IMPL_RANDBIT_DYNAMIC_BIT_TYPE(uint32_t);
IMPL_RANDBIT_DYNAMIC_BIT_TYPE(uint16_t);

}  // namespace yacl::crypto
