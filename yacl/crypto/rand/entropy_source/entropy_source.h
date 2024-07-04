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
// Entropy is defined relative to one’s knowledge of an experiment’s output
// prior to observation, and reflects the uncertainty associated with predicting
// its value – the larger the amount of entropy, the greater the uncertainty in
// predicting the value of an observation.
//
// NOTE: Each derived class should implement a different random entropy source,
// all implementations of entropy source should comply NIST SP800-90B, see:
// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90B.pdf
//
// NOTE: In the recommmend entropy source model, there's noise source,
// conditioning component and health tests. This base class is designed to only
// include the functionalities that allow external calls (e.g. generating the
// entropy output). In particular, we do not include the health tests API
// because it is not mandatory.
//
class EntropySource {
 public:
  // Constructor and desctructor
  EntropySource() = default;
  virtual ~EntropySource() = default;

  virtual std::string Name() = 0;

  // Get entropy with the request amount of entropy. By design, this function
  // should return the output of the conditioning component. For more details,
  // see NIST SP800-90B, section 2.2.
  //
  // NOTE: bits_of_entropy refers to the minimum required entropy estimate
  // results of the conditioning component, it does not necessarily means the
  // byte length of the output buffer.
  virtual Buffer GetEntropy(uint32_t bits_of_entropy) = 0;

  // This interface is meant to provide test data to credit a noise source with
  // an entropy estimate during validation or for external health testing
  //
  // virtual Buffer GetNoise() = 0;

  // You may also provide this api (not mandatory):
  // virtual bool HealthTest(Buffer buf);
};

class EntropySourceFactory final : public SpiFactoryBase<EntropySource> {
 public:
  static EntropySourceFactory& Instance() {
    static EntropySourceFactory factory;
    return factory;
  }
};

#define REGISTER_ENTROPY_SOURCE_LIBRARY(lib_name, performance, checker,    \
                                        creator)                           \
  REGISTER_SPI_LIBRARY_HELPER(EntropySourceFactory, lib_name, performance, \
                              checker, creator)

}  // namespace yacl::crypto
