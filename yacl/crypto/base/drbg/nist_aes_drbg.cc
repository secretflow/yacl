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

#include "yacl/crypto/base/drbg/nist_aes_drbg.h"

#include <algorithm>
#include <array>
#include <string>
#include <utility>

#include "absl/types/span.h"
#include "openssl/err.h"
#include "spdlog/spdlog.h"

#include "yacl/crypto/base/drbg/entropy_source.h"
#include "yacl/crypto/base/drbg/entropy_source_selector.h"

namespace yacl::crypto {

namespace {

// 128 32B; 192 40B; 256 48B
constexpr int kDefaultEntropyBytes = 48;
// 128 8B; 192 12B; 256 16B
constexpr int kDefaultNonceBytes = 16;
// health check data size
constexpr size_t kDefaultHealthCheckSize = 10;

//
// NIST SP800-90A Table 3
//    max request between reseed(reseed_interval) = 2^48;
// GB draft sm4_ctr_drbg reseed_interval is 210
// openssl aes_ctr_drbgdefault reseed_interval is 1<<16
constexpr int kReseedInterval = 1 << 8;

/*
 * Test context data, attached as EXDATA to the RAND_DRBG
 */
using ENTROPY_CTX = struct entropy_st {
  std::array<unsigned char, kDefaultEntropyBytes> entropy;
  size_t entropy_len = kDefaultEntropyBytes;
  int entropy_cnt = 0;
  std::array<unsigned char, kDefaultNonceBytes> nonce;
  size_t nonce_len = kDefaultNonceBytes;
  int nonce_cnt = 0;
  std::shared_ptr<IEntropySource> entropy_source;
};

size_t GetEntropy(RAND_DRBG *drbg, unsigned char **pout, int entropy_bits,
                  size_t min_len, size_t max_len, int prediction_resistance) {
  auto *ctx = reinterpret_cast<ENTROPY_CTX *>(
      RAND_DRBG_get_ex_data(drbg, NistAesDrbg::app_data_index_));

  ctx->entropy_cnt++;
  // key size + block size
  int entropy_bytes =
      std::max(min_len, static_cast<size_t>(entropy_bits / 8 + 16));

  std::string entropy_buffer = ctx->entropy_source->GetEntropy(entropy_bytes);

  YACL_ENFORCE((size_t)entropy_bytes == entropy_buffer.length());
  std::memcpy(ctx->entropy.data(), entropy_buffer.data(),
              entropy_buffer.length());

  *pout = static_cast<unsigned char *>(ctx->entropy.data());

  return entropy_bytes;
}

size_t GetNonce(RAND_DRBG *drbg, unsigned char **pout, int nonce_bits,
                size_t min_len, size_t max_len) {
  auto *ctx = reinterpret_cast<ENTROPY_CTX *>(
      RAND_DRBG_get_ex_data(drbg, NistAesDrbg::app_data_index_));

  ctx->nonce_cnt++;
  int nonce_bytes = std::max(min_len, static_cast<size_t>(nonce_bits / 8));

  std::string nonce_buffer = ctx->entropy_source->GetEntropy(nonce_bytes);
  std::memcpy(ctx->nonce.data(), nonce_buffer.data(), nonce_buffer.length());

  *pout = static_cast<unsigned char *>(ctx->nonce.data());
  return nonce_bytes;
}

void SetEntropyExData(RAND_DRBG *drbg,
                      const std::shared_ptr<IEntropySource> &entropy_source,
                      SecurityStrengthFlags security_strength) {
  auto *ctx = reinterpret_cast<ENTROPY_CTX *>(
      RAND_DRBG_get_ex_data(drbg, NistAesDrbg::app_data_index_));

  if (ctx == nullptr) {
    ctx = new ENTROPY_CTX();
    ctx->entropy_source = entropy_source;

    ctx->entropy_len = entropy_source->GetEntropyBytes(security_strength);
    ctx->entropy_cnt = 0;

    ctx->nonce_len = entropy_source->GetNonceBytes(security_strength);
    ctx->nonce_cnt = 0;
    YACL_ENFORCE(
        RAND_DRBG_set_ex_data(drbg, NistAesDrbg::app_data_index_, ctx));
  }
}

inline int GetPredictionResistance(
    PredictionResistanceFlags prediction_resistance) {
  int prediction_resistance_flag;
  switch (prediction_resistance) {
    case PredictionResistanceFlags::kYes:
      prediction_resistance_flag = 1;
      break;
    case PredictionResistanceFlags::kNo:
    default:
      prediction_resistance_flag = 0;
      break;
  }
  return prediction_resistance_flag;
}

}  // namespace

int NistAesDrbg::app_data_index_ =
    RAND_DRBG_get_ex_new_index(0L, nullptr, nullptr, nullptr, nullptr);

NistAesDrbg::NistAesDrbg(uint128_t personal_data,
                         SecurityStrengthFlags security_strength)
    : NistAesDrbg(nullptr, personal_data, security_strength) {}

NistAesDrbg::NistAesDrbg(std::shared_ptr<IEntropySource> entropy_source_ptr,
                         uint128_t personal_data,
                         SecurityStrengthFlags security_strength)
    : security_strength_(security_strength),
      entropy_source_(std::move(entropy_source_ptr)) {
  if (entropy_source_ == nullptr) {
    entropy_source_ = makeEntropySource();
  }

  unsigned int drbg_type;
  switch (security_strength_) {
    case SecurityStrengthFlags::kStrength256:
      drbg_type = NID_aes_256_ctr;
      break;
    case SecurityStrengthFlags::kStrength192:
      drbg_type = NID_aes_192_ctr;
      break;
    // now use aes key length 128 ctr mode
    case SecurityStrengthFlags::kStrength128:
    default:
      drbg_type = NID_aes_128_ctr;
      break;
  }

  ERR_load_ERR_strings();
  ERR_load_crypto_strings();
  ERR_load_BIO_strings();

  RAND_DRBG *drbg_ptr = RAND_DRBG_new(drbg_type, RAND_DRBG_FLAGS, nullptr);
  YACL_ENFORCE(drbg_ptr != nullptr);
  drbg_ = NistAesDrbg::RandDrbgPtr(drbg_ptr);

  SetEntropyExData(drbg_.get(), entropy_source_, security_strength_);

  YACL_ENFORCE(RAND_DRBG_set_callbacks(drbg_.get(), GetEntropy, nullptr,
                                       GetNonce, nullptr));

  ReSeed(kReseedInterval);

  Instantiate(personal_data);
}

NistAesDrbg::~NistAesDrbg() {
  if (drbg_ != nullptr) {
    UnInstantiate();
  }
}

std::vector<uint8_t> NistAesDrbg::Generate(
    size_t rand_len, PredictionResistanceFlags prediction_resistance) {
  std::vector<uint8_t> random_buf(rand_len);
  int prediction_resistance_flag =
      GetPredictionResistance(prediction_resistance);

  size_t out_len = 0;
  while (out_len < rand_len) {
    size_t request_len = std::min(max_rand_request_, rand_len - out_len);
    YACL_ENFORCE(RAND_DRBG_generate(drbg_.get(), random_buf.data() + out_len,
                                    request_len, prediction_resistance_flag,
                                    NULL, 0));
    out_len += request_len;
  }

  return random_buf;
}

void NistAesDrbg::Instantiate(uint128_t personal_string) {
  if (personal_string == 0) {
    YACL_ENFORCE(RAND_DRBG_instantiate(drbg_.get(), nullptr, 0));
  } else {
    YACL_ENFORCE(RAND_DRBG_instantiate(drbg_.get(),
                                       (const unsigned char *)&personal_string,
                                       sizeof(personal_string)));
  }
}

void NistAesDrbg::UnInstantiate() {
  auto *ctx = reinterpret_cast<ENTROPY_CTX *>(
      RAND_DRBG_get_ex_data(drbg_.get(), app_data_index_));

  delete ctx;
}

void NistAesDrbg::ReSeed(int reseed_interval) {
  RAND_DRBG_set_reseed_interval(drbg_.get(), reseed_interval);
}

bool NistAesDrbg::HealthCheck() {
  auto *ctx = reinterpret_cast<ENTROPY_CTX *>(
      RAND_DRBG_get_ex_data(drbg_.get(), NistAesDrbg::app_data_index_));

  std::array<uint64_t, kDefaultHealthCheckSize> random_buffer;
  std::array<uint64_t, kDefaultHealthCheckSize> entropy_buffer;

  FillPRand(absl::MakeSpan(reinterpret_cast<uint8_t *>(random_buffer.data()),
                           random_buffer.size() * sizeof(uint64_t)));

  for (size_t idx = 0; idx < kDefaultHealthCheckSize; idx++) {
    ctx->entropy_cnt++;
    entropy_buffer[idx] = ctx->entropy_source->GetEntropy();
  }

  for (size_t i = 0; i < kDefaultHealthCheckSize; i++) {
    for (size_t j = i + 1; j < kDefaultHealthCheckSize; j++) {
      if ((random_buffer[i] == random_buffer[j]) ||
          (entropy_buffer[i] == entropy_buffer[j])) {
        return false;
      }
    }
  }
  return true;
}

}  // namespace yacl::crypto
