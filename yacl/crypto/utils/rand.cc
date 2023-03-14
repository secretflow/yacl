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

#include "yacl/crypto/utils/rand.h"

#include <algorithm>
#include <mutex>
#include <thread>

#include "yacl/base/dynamic_bitset.h"

namespace yacl::crypto {

namespace {

std::once_flag seed_flag;

void OpensslSeedOnce() {
  // NistAesCtrDrbg seed with intel rdseed
  std::call_once(seed_flag, []() {
    Prg<uint64_t> prg(0, PRG_MODE::kNistAesCtrDrbg);
    std::array<uint8_t, 32> rand_bytes;
    prg.Fill(absl::MakeSpan(rand_bytes));  // get 256 bits seed

    RAND_seed(rand_bytes.data(), rand_bytes.size());  // reseed
  });
}
}  // namespace

// RAND_priv_bytes() and RAND_bytes() Generates num random bytes using a
// cryptographically secure pseudo random generator (CSPRNG) and stores them
// in out (with 256 security strength). For details, see:
// https://www.openssl.org/docs/man1.1.1/man3/RAND_bytes.html
//
// By default, the OpenSSL CSPRNG supports a security level of 256 bits,
// provided it was able to seed itself from a trusted entropy source.
// On all major platforms supported by OpenSSL (including the Unix-like
// platforms and Windows), OpenSSL is configured to automatically seed
// the CSPRNG on first use using the operating systems's random generator.
//
// OpenSSL comes with a default implementation of the RAND API which
// is based on the deterministic random bit generator (DRBG) model
// as described in [NIST SP 800-90A Rev. 1].
// It seeds and reseeds itself automatically using trusted random
// sources provided by the operating system.
//
// Reference:
// https://www.openssl.org/docs/man3.0/man7/RAND.html
// https://www.openssl.org/docs/man3.0/man3/RAND_seed.html
// https://www.openssl.org/docs/manmaster/man3/RAND_bytes.html

uint64_t RandU64(bool use_secure_rand) {
  uint64_t rand64;
  if (use_secure_rand) {
    OpensslSeedOnce();  // reseed openssl internal CSPRNG
    // RAND_priv_bytes() has the same semantics as RAND_bytes(). It uses a
    // separate "private" PRNG instance so that a compromise of the "public"
    // PRNG instance will not affect the secrecy of these private values
    //
    // RAND_priv_bytes() is thread-safe with OpenSSL >= 1.1.0
    YACL_ENFORCE(RAND_priv_bytes(reinterpret_cast<unsigned char*>(&rand64),
                                 sizeof(rand64)) == 1);

  } else {
    YACL_ENFORCE(RAND_bytes(reinterpret_cast<unsigned char*>(&rand64),
                            sizeof(uint64_t)) == 1);
  }
  return rand64;
}

uint128_t RandU128(bool use_secure_rand) {
  uint128_t rand128;
  if (use_secure_rand) {
    OpensslSeedOnce();  // reseed openssl internal CSPRNG
    // RAND_priv_bytes() has the same semantics as RAND_bytes(). It uses a
    // separate "private" PRNG instance so that a compromise of the "public"
    // PRNG instance will not affect the secrecy of these private values
    //
    // RAND_priv_bytes() is thread-safe with OpenSSL >= 1.1.0
    YACL_ENFORCE(RAND_priv_bytes(reinterpret_cast<unsigned char*>(&rand128),
                                 sizeof(rand128)) == 1);

  } else {
    YACL_ENFORCE(RAND_bytes(reinterpret_cast<unsigned char*>(&rand128),
                            sizeof(rand128)) == 1);
  }
  return rand128;
}

template <>
std::vector<bool> RandBits<std::vector<bool>>(uint64_t len,
                                              bool use_secure_rand) {
  std::vector<bool> out(len, false);
  const unsigned stride = sizeof(unsigned) * 8;
  if (use_secure_rand) {  // drbg is more secure
    Prg<unsigned> prg(RandU128(true), PRG_MODE::kNistAesCtrDrbg);
    for (uint64_t i = 0; i < len; i += stride) {
      unsigned rand = prg();
      unsigned size = std::min(stride, static_cast<unsigned>(len - i));
      for (unsigned j = 0; j < size; ++j) {
        out[i + j] = (rand & (1 << j)) != 0;
      }
    }
  } else {  // fast path
    Prg<unsigned> prg(RandU128(false), PRG_MODE::kAesEcb);
    for (uint64_t i = 0; i < len; i += stride) {
      unsigned rand = prg();
      unsigned size = std::min(stride, static_cast<unsigned>(len - i));
      for (unsigned j = 0; j < size; ++j) {
        out[i + j] = (rand & (1 << j)) != 0;
      }
    }
  }
  return out;
}

#define IMPL_RANDBIT_DYNAMIC_BIT_TYPE(TYPE)                                   \
  template <>                                                                 \
  dynamic_bitset<TYPE> RandBits<dynamic_bitset<TYPE>>(uint64_t len,           \
                                                      bool use_secure_rand) { \
    dynamic_bitset<TYPE> out(len);                                            \
    const unsigned stride = sizeof(unsigned) * 8;                             \
    if (use_secure_rand) {                                                    \
      Prg<unsigned> prg(RandU128(true), PRG_MODE::kNistAesCtrDrbg);           \
      for (uint64_t i = 0; i < len; i += stride) {                            \
        unsigned rand = prg();                                                \
        unsigned size = std::min(stride, static_cast<unsigned>(len - i));     \
        for (unsigned j = 0; j < size; ++j) {                                 \
          out[i + j] = (rand & (1 << j)) != 0;                                \
        }                                                                     \
      }                                                                       \
    } else {                                                                  \
      Prg<unsigned> prg(RandU128(false), PRG_MODE::kAesEcb);                  \
      for (uint64_t i = 0; i < len; i += stride) {                            \
        unsigned rand = prg();                                                \
        unsigned size = std::min(stride, static_cast<unsigned>(len - i));     \
        for (unsigned j = 0; j < size; ++j) {                                 \
          out[i + j] = (rand & (1 << j)) != 0;                                \
        }                                                                     \
      }                                                                       \
    }                                                                         \
    return out;                                                               \
  }

IMPL_RANDBIT_DYNAMIC_BIT_TYPE(uint128_t);
IMPL_RANDBIT_DYNAMIC_BIT_TYPE(uint64_t);
IMPL_RANDBIT_DYNAMIC_BIT_TYPE(uint32_t);
IMPL_RANDBIT_DYNAMIC_BIT_TYPE(uint16_t);

}  // namespace yacl::crypto
