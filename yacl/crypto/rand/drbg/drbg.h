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

#include "yacl/crypto/rand/entropy_source/entropy_source.h"
#include "yacl/secparam.h"
#include "yacl/utils/spi/spi_factory.h"

YACL_MODULE_DECLARE("drbg", SecParam::C::k256, SecParam::S::INF);

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

class Drbg {
 public:
  // constructor and destructor
  //
  // NOTE: the DRBG.instantiate function should be implemented by derived
  // classes in the class constructor. Also, DRBG.uninstantiate function should
  // be implemented in the class destructor
  //
  // NOTE: by default, the entropy source of DRBG uses the "auto" entropy source
  explicit Drbg(const std::shared_ptr<EntropySource>& es) : es_(es) {}
  virtual ~Drbg() = default;

  // reseed this drbg
  virtual void ReSeed() = 0;

  // fill the output with generated randomness
  virtual void Fill(char* buf, size_t len) = 0;

  // test the drbg instance
  // virtual void TestDrbg() = 0;

  // return the name of the implementation lib
  virtual std::string Name() = 0;

 protected:
  const std::shared_ptr<EntropySource>& es_;  // entropy source
};

// by default we want the DRBG has at least 128 bit security strength
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
