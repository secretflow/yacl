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

#include <memory>
#include <string>
#include <string_view>
#include <unordered_set>

#include "yacl/base/int128.h"
#include "yacl/crypto/openssl_wrappers.h"
#include "yacl/crypto/rand/drbg/drbg.h"
#include "yacl/crypto/rand/entropy_source/entropy_source.h"
#include "yacl/secparam.h"
#include "yacl/utils/spi/argument/arg_set.h"

namespace yacl::crypto {

// NIST SP 800-90A ctr-drbg, Recommendation for Random Number Generation Using
// Deterministic Random Bit Generators, see:
// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf
//
// For openssl docs, see: https://www.openssl.org/docs/man3.1/man3/EVP_RAND.html
class OpensslDrbg : public Drbg {
 public:
  // This is all the supported types of OpensslDrbg.
  static constexpr std::array<std::string_view, 3> TypeList = {
      "CTR-DRBG",
      "HASH-DRBG",
      "HMAC-DRBG",
  };

  // Constructor. "type" should one of the string in OpensslDrbg::TypeList; if
  // "use_yacl_es = true", this function will try to load yacl's entropy source,
  // and fallback to use openssl's default entropy source if failed to find
  // yacl's.
  explicit OpensslDrbg(std::string type, bool use_yacl_es = true,
                       SecParam::C secparam = SecParam::C::k128);

  // Destructor
  ~OpensslDrbg() override;

  // Create drbg instance
  static std::unique_ptr<Drbg> Create(const std::string &type,
                                      const SpiArgs &config) {
    YACL_ENFORCE(Check(type, config));  // make sure check passes
    return std::make_unique<OpensslDrbg>(
        absl::AsciiStrToUpper(type), config.GetOrDefault(ArgUseYaclEs, true),
        config.GetOrDefault(ArgSecParamC, SecParam::C::k128));
  }

  // This checker would return ture only for ctr-drbg type
  static bool Check(const std::string &type,
                    [[maybe_unused]] const SpiArgs &config) {
    return find(begin(TypeList), end(TypeList), absl::AsciiStrToUpper(type)) !=
           end(TypeList);
  }

  // Fill "buf" with random bytes with size "len".
  void Fill(char *buf, size_t len) final;

  // Get the lib name
  std::string Name() override { return "OpenSSL"; }

 private:
  const std::string type_;
  const SecParam::C secparam_;
  openssl::UniqueRandCtx ctx_;
};

REGISTER_DRBG_LIBRARY("OpenSSL", 100, OpensslDrbg::Check, OpensslDrbg::Create);

}  // namespace yacl::crypto
