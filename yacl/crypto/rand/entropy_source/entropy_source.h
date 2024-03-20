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

#include "yacl/base/buffer.h"
#include "yacl/secparam.h"
#include "yacl/utils/spi/spi_factory.h"

namespace yacl::crypto {

// Base class of Entropy Source (NIST SP800-90B)
//
// Each subclass should implement a different random entropy source, all
// implementations of entropy source should comply NIST SP800-90B, see:
// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90B.pdf
//
class EntropySource {
 public:
  // Constructor and desctructor
  EntropySource() = default;
  virtual ~EntropySource() = default;

  virtual std::string Name() = 0;

  // Get entropy with given amount of bytes
  virtual Buffer GetEntropy(uint32_t num_bytes) = 0;

  // You may also provide this api (not mandatory):
  // virtual Buffer GetNoise() = 0;

  // You may also provide this api (note mandatory):
  // virtual bool HealthTest(Buffer buf);
};

// by defalt we want the entropy source random has at least 128 bit security
// strength
// SpiArgKey<SecStrength> SecLevel("sec_level");
class EntropySourceFactory final : public SpiFactoryBase<EntropySource> {
 public:
  static EntropySourceFactory &Instance() {
    static EntropySourceFactory factory;
    return factory;
  }
};

#define REGISTER_ENTROPY_SOURCE_LIBRARY(lib_name, performance, checker,    \
                                        creator)                           \
  REGISTER_SPI_LIBRARY_HELPER(EntropySourceFactory, lib_name, performance, \
                              checker, creator)

}  // namespace yacl::crypto
