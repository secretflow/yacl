// Copyright 2020 Ant Group Co., Ltd.
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

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_set>

#include "yacl/base/byte_container_view.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/openssl_wrappers.h"
#include "yacl/crypto/rand/drbg/drbg.h"
#include "yacl/crypto/rand/entropy_source/entropy_source.h"
#include "yacl/secparam.h"
#include "yacl/utils/spi/argument/arg_set.h"

/* submodules */
#include "yacl/crypto/block_cipher/symmetric_crypto.h"

namespace yacl::crypto {

// internal implementation
// note: those class/functions are not designed to be called externally
namespace internal {

// ----------------------------------------
// GM/T 0105-2021 《软件随机数发生器设计指南》
//     附录E（规范性） 基于 SM4 算法的 RNG 设计
// 注意：本实现仅使用了 OpenSSL 提供的 SM4-ECB
// ----------------------------------------
class Sm4Drbg {
 public:
  // default values
  constexpr static auto kCodeType = SymmetricCrypto::CryptoType::SM4_ECB;
  constexpr static uint32_t kBlockSize = 16;      /* 128 bits = 16 bytes */
  constexpr static uint32_t kKeySize = 16;        /* 128 bits = 16 bytes */
  constexpr static uint32_t kMinEntropySize = 32; /* 256 bits = 32 bytes */
  constexpr static uint32_t kSeedlen = 32;        /* outlen + keylen */
  constexpr static uint32_t kMaxEntropySize =
      std::numeric_limits<uint32_t>::max(); /* 2^35 bits = 2^32 bytes */

  // Constructor
  explicit Sm4Drbg(SecParam::C secparam = SecParam::C::k128);
  explicit Sm4Drbg(const SecParam::C &secparam);

  // Instantiate the drbg
  // * nonce: 128 bits (16 bytes) <= nonce bit num < 2^34
  // * personal_string >= 0 bytes (optional)
  void Instantiate(ByteContainerView nonce,
                   ByteContainerView personal_string = "");

  // Generate randomness
  Buffer Generate(size_t len, ByteContainerView additional_input = "");

 private:
  // drbg internal working state
  struct InteralWorkingState {
    uint128_t v;
    uint128_t key;
    size_t reseed_ctr = 1;                /* starts with 1 */
    size_t reseed_interval_ctr = 1 << 10; /*  */
    uint64_t last_reseed_time = 0;        /* in seconds */
    uint64_t reseed_interval_time;        /* in seconds */
  };

  // use buf to update the values of key and v
  void rng_update(ByteContainerView seed_buf, uint128_t key, uint128_t v,
                  uint128_t *out_key, uint128_t *out_v);

  // derive randomness from seed_buf
  Buffer derive(ByteContainerView buf, /* out bytes */ uint32_t out_len);

  // calculate cbc mac with given key and data
  std::array<uint8_t, kBlockSize> cbc_mac(uint128_t key,
                                          ByteContainerView data);

  // reseed the internal state with additional_input
  void reseed(ByteContainerView additional_input);

  // Q: why not use SymmetricCrypto in crypto/base/block_cipher?
  // A: SymmetricCrypto is originally designed to be use to entrypt large amount
  // of plaintexts with the same key, and in DRBG we need to change the key
  // oftenly. It's more efficient to use openssl's native APIs.
  openssl::UniqueCipher cipher_;
  openssl::UniqueCipherCtx cipher_ctx_;

  InteralWorkingState internal_state_;
};

}  // namespace internal

// by default all native drbg use yacl's entropy source
class NativeDrbg : public Drbg {
 public:
  static constexpr std::array<std::string_view, 1> TypeList = {
      "GM-DRBG",
  };

  explicit NativeDrbg(std::string type, bool use_yacl_es = true,
                      SecParam::C secparam = SecParam::C::k128);

  // create drbg instance
  static std::unique_ptr<Drbg> Create(const std::string &type,
                                      const SpiArgs &config) {
    YACL_ENFORCE(Check(type, config));  // make sure check passes
    return std::make_unique<NativeDrbg>(
        absl::AsciiStrToUpper(type), config.GetOrDefault(ArgUseYaclEs, true),
        config.GetOrDefault(ArgSecParamC, SecParam::C::k128));
  }

  // this checker would return ture only for ctr-drbg type
  static bool Check(const std::string &type,
                    [[maybe_unused]] const SpiArgs &config) {
    return find(begin(TypeList), end(TypeList), absl::AsciiStrToUpper(type)) !=
           end(TypeList);
  }

  // fill buffer with randomness
  void Fill(char *buf, size_t len) final;

  // get the lib name
  std::string Name() override { return "NativeImpl"; }

 private:
  const std::string type_;
  const SecParam::C secparam_;

  /* native implementation pointers */
  std::unique_ptr<internal::Sm4Drbg> drbg_impl_;
};

REGISTER_DRBG_LIBRARY("NativeImpl", 100, NativeDrbg::Check, NativeDrbg::Create);

}  // namespace yacl::crypto
