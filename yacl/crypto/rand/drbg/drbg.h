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
#include <utility>

#include "yacl/base/exception.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/rand/entropy_source/entropy_source.h"
#include "yacl/secparam.h"
#include "yacl/utils/spi/spi_factory.h"

namespace yacl::crypto {

// -----------------------------------
// Base class of DRBG (NIST SP800-90A)
// -----------------------------------
// DRBG: Deterministic Random Bit Generator. Each subclass should implement a
// different DRBG , all implementations of DRBG should comply NIST SP800-90A,
// see:
// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90A.pdf
//
// ---------------
// Usage:
//   auto drbg = DrbgFactory::Instance().Create("ctr-drbg");
// ----------------
// Currently, the supported drbg types are (case insensitive):
// * "CTR-DRBG"
// * "HASH-DRBG"
// * "HMAC-DRBG"

DEFINE_ARG_bool(UseYaclEs);          // spi args, default should be true
DEFINE_ARG(SecParam::C, SecParamC);  // spi args, default should >= 128

class Drbg {
 public:
  // constructor and destructor
  explicit Drbg(bool use_yacl_es = true, SecParam::C c = SecParam::C::k128)
      : use_yacl_es_(use_yacl_es), c_(c) {}
  virtual ~Drbg() = default;

  // fill the output with generated randomness
  virtual void Fill(char* buf, size_t len) = 0;

  // set the seed for this drbg
  // [warning]: this feature may not be allowed by all implementations
  virtual void SetSeed([[maybe_unused]] uint128_t seed) {
    YACL_THROW("Set Seed is not Allowed");
  }

  // return the name of the implementation lib
  virtual std::string Name() = 0;

 protected:
  const bool use_yacl_es_;  // whether use yacl's entropy source
  const SecParam::C c_;     // comp. security parameter
};

// by defalt we want the DRBG has at least 128 bit security strength
class DrbgFactory final : public SpiFactoryBase<Drbg> {
 public:
  static DrbgFactory& Instance() {
    static DrbgFactory factory;
    return factory;
  }
};

#define REGISTER_DRBG_LIBRARY(lib_name, performance, checker, creator)     \
  REGISTER_SPI_LIBRARY_HELPER(DrbgFactory, lib_name, performance, checker, \
                              creator)

}  // namespace yacl::crypto
