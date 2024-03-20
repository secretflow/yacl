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

#include <memory>
#include <string>
#include <string_view>
#include <unordered_set>

#include "hash_drbg.h"  // from @com_github_greendow_hash_drbg//:hash_drbg

#include "yacl/base/int128.h"
#include "yacl/crypto/rand/drbg/drbg.h"
#include "yacl/crypto/rand/entropy_source/entropy_source.h"
#include "yacl/secparam.h"
#include "yacl/utils/spi/argument/arg_set.h"

namespace yacl::crypto {

// NIST SP 800-90A hash-drbg, Recommendation for Random Number Generation Using
// Deterministic Random Bit Generators, see:
// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf
//
class IcDrbg : public Drbg {
 public:
  static constexpr std::array<std::string_view, 1> TypeList = {
      "IC-HASH-DRBG",
  };

  explicit IcDrbg(std::string type, bool use_yacl_es = true,
                  SecParam::C secparam = SecParam::C::k128);
  ~IcDrbg() override = default;

  // create drbg instance
  static std::unique_ptr<Drbg> Create(const std::string &type,
                                      const SpiArgs &config) {
    YACL_ENFORCE(Check(type, config));  // make sure check passes
    return std::make_unique<IcDrbg>(
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

  // set seed
  void SetSeed(uint128_t seed) final;

  // get the lib name
  std::string Name() override { return "Interconnection"; }

 private:
  uint128_t seed_ = 0;
  const std::string type_;
  const SecParam::C secparam_;
  HASH_DRBG_CTX *drbg_ctx_;
};

REGISTER_DRBG_LIBRARY("Interconnection", 100, IcDrbg::Check, IcDrbg::Create);

}  // namespace yacl::crypto
