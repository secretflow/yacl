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
#include "yacl/crypto/rand/entropy_source/entropy_source.h"
#include "yacl/math/gadget.h"

namespace yacl::crypto {

namespace {

// A thread-safe random context class
class RandCtx {
 public:
  explicit RandCtx() {
    // default drbg = openssl drbg with yacl's entropy source
    ctr_drbg_ = DrbgFactory::Instance().Create("ctr-drbg");
    hash_drbg_ = DrbgFactory::Instance().Create("hash-drbg");
  }

  // get a static default context
  static RandCtx &GetDefault() {
    static auto ctx = RandCtx();
    return ctx;
  }

  // fill random to buf with len (warning: does not check boundaries)
  void Fill(char *buf, size_t len, bool fast_mode = false) const {
    YACL_ENFORCE(len <= std::numeric_limits<int>::max());
    if (fast_mode) {
      hash_drbg_->Fill(buf, len);  // those drbg automatically reseeds
    } else {
      ctr_drbg_->Fill(buf, len);  // those drbg automatically reseeds
    }
  }

 private:
  // https://crypto.stackexchange.com/a/1395/61581
  std::unique_ptr<Drbg> ctr_drbg_;
  std::unique_ptr<Drbg> hash_drbg_;  // faster
};

}  // namespace

void FillRand(char *buf, size_t len, bool fast_mode) {
  RandCtx::GetDefault().Fill(buf, len, fast_mode);
}

// ---------------------
// Other Implementations
// ---------------------
//
uint32_t RandU32(bool fast_mode) {
  uint32_t rand32 = 0;
  FillRand(reinterpret_cast<char *>(&rand32), sizeof(uint32_t), fast_mode);
  return rand32;
}

uint64_t RandU64(bool fast_mode) {
  uint64_t rand64 = 0;
  FillRand(reinterpret_cast<char *>(&rand64), sizeof(uint64_t), fast_mode);
  return rand64;
}

uint128_t RandU128(bool fast_mode) {
  uint128_t rand128 = 0;
  FillRand(reinterpret_cast<char *>(&rand128), sizeof(uint128_t), fast_mode);
  return rand128;
}

template <>
std::vector<bool> RandBits<std::vector<bool>>(uint64_t len, bool fast_mode) {
  std::vector<bool> out(len, false);
  const unsigned stride = sizeof(unsigned) * 8;

  // generate randomness
  auto rand_buf = RandVec<unsigned>(len, fast_mode);

  // for each byte
  for (uint64_t i = 0; i < len; i += stride) {
    unsigned size = std::min(stride, static_cast<unsigned>(len - i));
    for (unsigned j = 0; j < size; ++j) {
      out[i + j] = (rand_buf[i] & (1 << j)) != 0;
    }
  }
  return out;
}

std::vector<uint8_t> RandBytes(uint64_t len, bool fast_mode) {
  std::vector<uint8_t> out(len);
  FillRand(reinterpret_cast<char *>(out.data()), len, fast_mode);
  return out;
}

std::vector<uint8_t> FastRandBytes(uint64_t len) {
  return RandBytes(len, true);
}

std::vector<uint8_t> SecureRandBytes(uint64_t len) {
  return RandBytes(len, false);
}

#define SPECIFY_RANDBIT_TEMPLATE(T)                                           \
  template <>                                                                 \
  dynamic_bitset<T> RandBits<dynamic_bitset<T>>(uint64_t len,                 \
                                                bool fast_mode) {             \
    dynamic_bitset<T> out(len);                                               \
    size_t byte_len = math::DivCeil(len, 8);                                  \
                                                                              \
    /* generate randomness */                                                 \
    auto rand_buf = RandBytes(byte_len, fast_mode);                           \
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

SPECIFY_RANDBIT_TEMPLATE(uint128_t);
SPECIFY_RANDBIT_TEMPLATE(uint64_t);
SPECIFY_RANDBIT_TEMPLATE(uint32_t);
SPECIFY_RANDBIT_TEMPLATE(uint16_t);

#undef SPECIFY_RANDBIT_TEMPLATE

}  // namespace yacl::crypto
