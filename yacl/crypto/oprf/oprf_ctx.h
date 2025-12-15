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

struct Proof {
  math::MPInt c;
  math::MPInt s;
};

// rfc8017 4.1 I2OSP
// I2OSP - Integer-to-Octet-String primitive
// Input:
//   x        nonnegative integer to be converted
//   xlen     intended length of the resulting octet string
// Output:
//   X corresponding octet string of length xLen
// Error : "integer too large"
std::vector<uint8_t> I2OSP(size_t x, size_t xlen) {
  YACL_ENFORCE(x < std::pow(256, xlen), "integer too large");

  yacl::ByteContainerView xbytes(&x, xlen);

  std::vector<uint8_t> ret(xlen);
  std::memcpy(ret.data(), xbytes.data(), xlen);

  if (xlen > 1) {
    std::reverse(ret.begin(), ret.end());
  }
  return ret;
}

// ---------- //
// Oprf Enums //
// ---------- //
enum class OprfMode : uint8_t { OPRF = 0x00, VOPRF = 0x01, POPRF = 0x02 };

enum class OprfCipherSuite : int {
  ristretto255_Sha512,  // Supported via libsodium
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
  // static uint8_t ModeToU8(OprfMode mode) { return static_cast<uint8_t>(mode);
  // }
  static char ModeToU8(OprfMode mode) { return static_cast<char>(mode); }

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

  static OprfConfig& GetVOPRFDefault() {
    static OprfConfig config(OprfMode::VOPRF, kDefaultCipherSuite);
    return config;
  }

  static OprfConfig& GetPOPRFDefault() {
    static OprfConfig config(OprfMode::POPRF, kDefaultCipherSuite);
    return config;
  }

  // Get the defined oprf mode
  OprfMode GetMode() const { return mode_; }

  // Get the defined oprf mode
  OprfCipherSuite GetCipherSuite() const { return cipher_suite_; }

  // Convert the information to context string
  //  OPRF Context String: "OPRFV1-" || I2OSP(mode, 1) || "-" || ciphersuite
  //  identifier mode for OPRF protocol variants: modeOPRF  - 0x00 modeVOPRF -
  //  0x01 modePOPRF - 0x02
  // FIXME: mode_ should be unprintable char /x0, /x1, /x2
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
    cipher_suite_ = config.GetCipherSuite();
    // auto t = DecomposeCipherSuite(config.GetCipherSuite());
    auto t = DecomposeCipherSuite(cipher_suite_);
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
  std::pair<SkTy, PkTy> DeriveKeyPair(std::array<char, 32> seed,
                                      const std::string& info = "");

  // Statistcally decompose the cipher suite object to valid EcGroup and
  // HashAlgorithm objects
  static std::pair<std::unique_ptr<EcGroup>, HashAlgorithm>
  DecomposeCipherSuite(const OprfCipherSuite& cipher_suite) {
    switch (cipher_suite) {
      case OprfCipherSuite::ristretto255_Sha512:
        return {EcGroupFactory::Instance().Create("ristretto255",
                                                  yacl::ArgLib = "libsodium"),
                HashAlgorithm::SHA512};
      case OprfCipherSuite::decaf448_SHAKE256:
        // return {EcGroupFactory::Instance().Create("decaf448"),
        //         HashAlgorithm::SHAKE512};
        YACL_THROW("Unsupported cipher suite: decaf448_SHAKE256");
      case OprfCipherSuite::P256_SHA256:
        return {EcGroupFactory::Instance().Create("secp256r1",
                                                  yacl::ArgLib = "openssl"),
                HashAlgorithm::SHA256};
      case OprfCipherSuite::P384_SHA384:
        return {EcGroupFactory::Instance().Create("secp384r1",
                                                  yacl::ArgLib = "openssl"),
                HashAlgorithm::SHA384};
      case OprfCipherSuite::P521_SHA512:
        return {EcGroupFactory::Instance().Create("secp521r1",
                                                  yacl::ArgLib = "openssl"),
                HashAlgorithm::SHA512};
      default:
        YACL_THROW(
            "Decompose Oprf Cipher Suite failure, unknown CipherSuite "
            "code: {}",
            (int)cipher_suite);
    }
  }

  std::string GetContextString() const { return ctx_str_; }

  absl::string_view GetContextView() const { return ctx_str_; }

  // ec group operations
  // FIXME: HashToGroup
  EcPoint HashToGroup(std::string_view str,
                      std::string_view prefix = "HashToGroup-") {
    std::string dst = std::string(prefix) + ctx_str_;
    switch (cipher_suite_) {
      case OprfCipherSuite::ristretto255_Sha512:
        return ec_->HashToCurve(HashToCurveStrategy::SHA512_R255MAP_RO_, str, dst);
      case OprfCipherSuite::decaf448_SHAKE256:
        YACL_THROW("Unsupported cipher suite: decaf448_SHAKE256");
      case OprfCipherSuite::P256_SHA256:
        return ec_->HashToCurve(HashToCurveStrategy::SHA256_SSWU_RO_, str, dst);
      case OprfCipherSuite::P384_SHA384:
        return ec_->HashToCurve(HashToCurveStrategy::SHA384_SSWU_NU_, str, dst);
      case OprfCipherSuite::P521_SHA512:
        return ec_->HashToCurve(HashToCurveStrategy::SHA512_SSWU_NU_, str, dst);
      default:
        YACL_THROW("HashToGroup failure, unknown CipherSuite code: {}",
                   (int)cipher_suite_);
    }
  }

  yacl::math::MPInt HashToScalar(std::string_view str,
                                 std::string_view prefix = "HashToScalar-") {
    std::string dst = std::string(prefix) + ctx_str_;
    switch (cipher_suite_) {
      case OprfCipherSuite::ristretto255_Sha512:
        return ec_->HashToScalar(HashToCurveStrategy::Ristretto255_SHA512_, str, dst);
      case OprfCipherSuite::decaf448_SHAKE256:
        YACL_THROW("Unsupported cipher suite: decaf448_SHAKE256");
      case OprfCipherSuite::P256_SHA256:
        return ec_->HashToScalar(HashToCurveStrategy::P256_SHA256_, str, dst);
      case OprfCipherSuite::P384_SHA384:
        return ec_->HashToScalar(HashToCurveStrategy::P384_SHA384_, str, dst);
      case OprfCipherSuite::P521_SHA512:
        return ec_->HashToScalar(HashToCurveStrategy::P521_SHA512_, str, dst);
      default:
        YACL_THROW("HashToScalar failure, unknown CipherSuite code: {}",
                   (int)cipher_suite_);
    }
  }

 private:
  std::string ctx_str_;
  OprfMode mode_;
  std::unique_ptr<EcGroup> ec_;
  HashAlgorithm hash_;
  OprfCipherSuite cipher_suite_;
};

}  // namespace yacl::crypto
