// Copyright 2024 Ant Group Co., Ltd.
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
#include <utility>
#include <vector>

#include "absl/strings/str_split.h"

#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/crypto/hash/hash_interface.h"

namespace yacl::crypto {

// ---------- //
// Oprf Enums //
// ---------- //
enum class OprfMode : uint8_t { OPRF = 0x00, VOPRF = 0x01, POPRF = 0x02 };

enum class OprfCipherSuite : int {
  ristretto255_Sha512,  // FIXME unsupported
  decaf448_SHAKE256,    // FIXME unsupported
  P256_SHA256,
  P384_SHA384,
  P521_SHA512,
};

// ------------------ //
// Helper Oprf Config //
// ------------------ //
class OprfConfig {
 public:
  // Default config values
  static constexpr OprfMode kDefaultMode = OprfMode::OPRF;
  static constexpr OprfCipherSuite kDefaultCipherSuite =
      OprfCipherSuite::P256_SHA256;

  // Static helper functions
  static OprfCipherSuite CipherSuiteFromStr(const std::string& str) {
    if (str == "ristretto255-SHA512") {
      return OprfCipherSuite::ristretto255_Sha512;
    } else if (str == "decaf448-SHAKE256") {
      return OprfCipherSuite::decaf448_SHAKE256;
    } else if (str == "P256-SHA256") {
      return OprfCipherSuite::P256_SHA256;
    } else if (str == "P384-SHA384") {
      return OprfCipherSuite::P384_SHA384;
    } else if (str == "P521-SHA512") {
      return OprfCipherSuite::P521_SHA512;
    } else {
      YACL_THROW("Unrecognized Cipher Suite String: {}", str);
    }
  }

  static std::string CipherSuiteToStr(const OprfCipherSuite& cipher_suite) {
    switch (cipher_suite) {
      case OprfCipherSuite::ristretto255_Sha512:
        return "ristretto255-SHA512";
      case OprfCipherSuite::decaf448_SHAKE256:
        return "decaf448-SHAKE256";
      case OprfCipherSuite::P256_SHA256:
        return "P256-SHA256";
      case OprfCipherSuite::P384_SHA384:
        return "P384-SHA384";
      case OprfCipherSuite::P521_SHA512:
        return "P521-SHA512";
      default:
        YACL_THROW("Unrecognized Cipher Suite code: {}", (int)cipher_suite);
    }
  }
  static OprfMode ModeFromU8(uint8_t x) { return static_cast<OprfMode>(x); }
  static uint8_t ModeToU8(OprfMode mode) { return static_cast<uint8_t>(mode); }

  // Constructors
  OprfConfig(const OprfMode& mode, const OprfCipherSuite& cipher_suite)
      : mode_(mode), cipher_suite_(cipher_suite) {}

  OprfConfig(uint8_t mode, const std::string& cipher_suite)
      : OprfConfig(ModeFromU8(mode), CipherSuiteFromStr(cipher_suite)) {}

  // Grab a default OprfConfig, it makes life easier
  static OprfConfig& GetDefault() {
    static OprfConfig config(kDefaultMode, kDefaultCipherSuite);
    return config;
  }

  // Get the defined oprf mode
  OprfMode GetMode() const { return mode_; }

  // Get the defined oprf mode
  OprfCipherSuite GetCipherSuite() const { return cipher_suite_; }

  // Convert the information to context string
  std::string ToContextString() const {
    return fmt::format("OPRFV1-{}-{}", ModeToU8(mode_),
                       CipherSuiteToStr(cipher_suite_));
  }

  // Get config from context string
  static OprfConfig FromContextString(const std::string& str) {
    std::vector<std::string> split = absl::StrSplit(str, '-');
    YACL_ENFORCE(split.size() == 3);
    YACL_ENFORCE_EQ(split[0], "OPRFV1");
    YACL_ENFORCE(split[1].size() == 1);
    auto mode = ModeFromU8(static_cast<uint8_t>(split[1][0]));
    auto cipher_suite = CipherSuiteFromStr(split[2]);
    return {mode, cipher_suite};
  }

 private:
  OprfMode mode_;
  OprfCipherSuite cipher_suite_;
};

// --------------------------- //
//        Oprf Context
// --------------------------- //

class OprfCtx {
 public:
  using SkTy = math::MPInt;
  using PkTy = EcPoint;

  // Constructor from oprf config
  explicit OprfCtx(const OprfConfig& config) : mode_(config.GetMode()) {
    ctx_str_ = config.ToContextString();
    auto t = DecomposeCipherSuite(config.GetCipherSuite());
    ec_ = std::move(t.first);
    hash_ = t.second;
  }

  // Constructor from context string
  explicit OprfCtx(const std::string& ctx_str)
      : OprfCtx(OprfConfig::FromContextString(ctx_str)) {}

  // Grab a default OprfConfig, it makes life easier
  static OprfCtx& GetDefault() {
    static OprfCtx ctx(OprfConfig::GetDefault());
    return ctx;
  }

  // Steal the extracted ec group from OprfConfig, the ec_ definied in
  // OprfConfig will be reset. Therefore, this function should be called at
  // most once for one OprfConfig instance.
  //
  // NOTE be careful when you steal things
  //
  std::unique_ptr<EcGroup> StealEcGroup() { return std::move(ec_); }

  // Borrwo the ec group from context, ec group's lifetime stays with in
  // OprfCtx
  EcGroup* BorrowEcGroup() { return ec_.get(); }

  // Get the defined hash algorithm
  HashAlgorithm GetHashAlgorithm() const { return hash_; }

  // Get the defined oprf mode
  OprfMode GetMode() const { return mode_; }

  // Generate random key pair
  std::pair<SkTy, PkTy> GenKeyPair();

  // Extract deterministic key pair from seed and info
  std::pair<SkTy, PkTy> DeriveKeyPair(uint128_t seed,
                                      const std::string& info = "");

  // Statistcally decompose the cipher suite object to valid EcGroup and
  // HashAlgorithm objects
  static std::pair<std::unique_ptr<EcGroup>, HashAlgorithm>
  DecomposeCipherSuite(const OprfCipherSuite& cipher_suite) {
    switch (cipher_suite) {
      case OprfCipherSuite::ristretto255_Sha512:
        YACL_THROW("Unsupported cipher suite: ristretto255_Sha512");
        // return {EcGroupFactory::Instance().Create("ristretto255"),
        //         HashAlgorithm::SHA512};
      case OprfCipherSuite::decaf448_SHAKE256:
        // return {EcGroupFactory::Instance().Create("decaf448"),
        //         HashAlgorithm::SHAKE512};
        YACL_THROW("Unsupported cipher suite: decaf448_SHAKE256");
      case OprfCipherSuite::P256_SHA256:
        return {EcGroupFactory::Instance().Create("brainpoolP256r1"),
                HashAlgorithm::SHA256};
      case OprfCipherSuite::P384_SHA384:
        return {EcGroupFactory::Instance().Create("brainpoolP384r1"),
                HashAlgorithm::SHA384};
      case OprfCipherSuite::P521_SHA512:
        return {EcGroupFactory::Instance().Create("brainpoolP512r1"),
                HashAlgorithm::SHA512};
      default:
        YACL_THROW(
            "Decompose Oprf Cipher Suite failure, unknown CipherSuite "
            "code: {}",
            (int)cipher_suite);
    }
  }

 private:
  std::string ctx_str_;
  OprfMode mode_;
  std::unique_ptr<EcGroup> ec_;
  HashAlgorithm hash_;
};

}  // namespace yacl::crypto
