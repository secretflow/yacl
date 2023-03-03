// Copyright 2019 Ant Group Co., Ltd.
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

#include <memory>
#include <string>
#include <vector>

#include "absl/types/span.h"
#include "spdlog/spdlog.h"

#include "yacl/base/byte_container_view.h"
#include "yacl/base/exception.h"
#include "yacl/crypto/base/drbg/drbg.h"
#include "yacl/crypto/base/drbg/entropy_source.h"
#include "yacl/crypto/base/drbg/entropy_source_selector.h"
#include "yacl/crypto/base/symmetric_crypto.h"

namespace yacl::crypto {

class EvpCipherDeleter {
 public:
  void operator()(EVP_CIPHER_CTX* ctx) { EVP_CIPHER_CTX_free(ctx); }
};

typedef std::unique_ptr<EVP_CIPHER_CTX, EvpCipherDeleter> EvpCipherPtr;

inline constexpr size_t kBlockSize = 16;

//
// 《软件随机数设计指南》- 征求意见稿
//     附录B 基于SM4_CTR的RNG设计
//
class Sm4Drbg : public IDrbg {
 public:
  Sm4Drbg(uint128_t personal_data, SymmetricCrypto::CryptoType crypto_type =
                                       SymmetricCrypto::CryptoType::SM4_ECB)
      : Sm4Drbg(crypto_type) {
    // call Instantiate
    if (personal_data != 0) {
      Instantiate(ByteContainerView(reinterpret_cast<uint8_t*>(&personal_data),
                                    sizeof(personal_data)));
    } else {
      Instantiate();
    }
  }

  Sm4Drbg(const std::shared_ptr<IEntropySource>& entropy_source_ptr,
          SymmetricCrypto::CryptoType crypto_type =
              SymmetricCrypto::CryptoType::SM4_ECB)
      : ecb_ctx_(EVP_CIPHER_CTX_new()),
        entropy_source_(entropy_source_ptr),
        crypto_type_(crypto_type) {
    if (entropy_source_ == nullptr) {
      entropy_source_ = makeEntropySource();
    }

    EVP_CIPHER_CTX_init(ecb_ctx_.get());
  }

  Sm4Drbg(SymmetricCrypto::CryptoType crypto_type =
              SymmetricCrypto::CryptoType::SM4_ECB)
      : Sm4Drbg(nullptr, crypto_type) {}

  void Instantiate(ByteContainerView personal_string = "");

  std::vector<uint8_t> Generate(size_t rand_length);
  std::vector<uint8_t> Generate(size_t rand_length,
                                absl::Span<const uint8_t> additional_input);

  void FillPRandBytes(absl::Span<uint8_t> out) override;

 private:
  void RngUpdate();
  void Inc128();

  void ReSeed(absl::Span<const uint8_t> seed);
  void ReSeed(absl::Span<const uint8_t> seed,
              absl::Span<const uint8_t> additional_input);

  // output seed_length_ new seed_material
  std::string RngDf(ByteContainerView seed_material);

  //
  std::array<uint8_t, kBlockSize> CbcMac(absl::Span<const uint8_t> key,
                                         absl::Span<const uint8_t> data_to_mac);

  EvpCipherPtr ecb_ctx_;

  //
  std::array<uint8_t, kBlockSize> key_;
  std::array<uint8_t, kBlockSize> v_;

  uint64_t reseed_counter_ = 0;

  // security level 1 2^10
  // security level 2 1
  uint64_t reseed_interval_ = 1 << 10;

  uint64_t seed_length_ = 32;

  uint64_t min_length_ = 16;

  uint64_t min_entropy_ = 0;
  std::string entropy_input_;

  std::string seed_material_;

  std::shared_ptr<IEntropySource> entropy_source_;

  SymmetricCrypto::CryptoType crypto_type_ =
      SymmetricCrypto::CryptoType::SM4_ECB;
};

}  // namespace yacl::crypto
