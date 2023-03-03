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

#include <algorithm>
#include <iostream>
#include <memory>
#include <vector>

#include "absl/types/span.h"
#include "openssl/crypto.h"
#include "openssl/rand.h"
#include "openssl/rand_drbg.h"

#include "yacl/base/byte_container_view.h"
#include "yacl/base/exception.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/base/drbg/drbg.h"
#include "yacl/crypto/base/drbg/entropy_source.h"

namespace yacl::crypto {

enum class PredictionResistanceFlags { kNo, kYes };

//
// based on NIST SP 800-90A ctr-drbg
// Recommendation for Random Number Generation Using Deterministic Random Bit
// Generators
// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf
//
class NistAesDrbg : public IDrbg {
 public:
  NistAesDrbg(uint128_t personal_data = 0,
              SecurityStrengthFlags security_strength =
                  SecurityStrengthFlags::kStrength128);

  NistAesDrbg(std::shared_ptr<IEntropySource> entropy_source_ptr,
              uint128_t personal_data = 0,
              SecurityStrengthFlags security_strength =
                  SecurityStrengthFlags::kStrength128);

  ~NistAesDrbg();

  SecurityStrengthFlags GetSecurityStrength() const {
    return security_strength_;
  }

  // rand_len: random bytes
  // PredictionResistance enabled will immediately call reseed
  // PredictionResistance not enabled, check reseed_interval
  // default PredictionResistance not enabled
  std::vector<uint8_t> Generate(
      size_t rand_len, PredictionResistanceFlags prediction_resistance =
                           PredictionResistanceFlags::kNo);

  void FillPRandBytes(absl::Span<uint8_t> out) override {
    const size_t nbytes = out.size();

    size_t out_len = 0;
    while (out_len < nbytes) {
      size_t reqeust_len = std::min(max_rand_request_, nbytes - out_len);
      YACL_ENFORCE(RAND_DRBG_generate(drbg_.get(),
                                      (unsigned char*)out.data() + out_len,
                                      reqeust_len, 0, NULL, 0));
      out_len += reqeust_len;
    }
  }

  bool HealthCheck();

  static int app_data_index_;

  class RandDrbgDeleter {
   public:
    void operator()(RAND_DRBG* drbg) {
      RAND_DRBG_uninstantiate(drbg);
      RAND_DRBG_free(drbg);
    }
  };
  using RandDrbgPtr = std::unique_ptr<RAND_DRBG, RandDrbgDeleter>;

 private:
  void Instantiate(uint128_t personal_string = 0);
  void UnInstantiate();

  void ReSeed(int reseed_interval);

  RandDrbgPtr drbg_;

  // strength: 128, 192, 256
  const SecurityStrengthFlags security_strength_;
  std::shared_ptr<IEntropySource> entropy_source_;

  size_t max_rand_request_ = 1 << 16;
};

}  // namespace yacl::crypto
