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

#include <string>

#include "yacl/crypto/base/drbg/entropy_source.h"

namespace yacl::crypto {
// Intel Digital Random Number Generator (DRNG) Software Implementation Guide
// reference:
// https://software.intel.com/en-us/articles/intel-digital-random-number-generator-drng-software-implementation-guide/
// use intel DRNG as entropy source
// libdrng-1.0.zip
// https://software.intel.com/content/www/us/en/develop/articles/the-drng-library-and-manual.html
// intel ipp-crypto
// https://www.intel.com/content/www/us/en/develop/documentation/ipp-crypto-reference/top/public-key-cryptography-functions/pseudorandom-number-generation-functions/trngenrdseed.html
//

class IntelEntropySource : public IEntropySource {
 public:
  IntelEntropySource();
  ~IntelEntropySource() override = default;

  std::string GetEntropy(size_t entropy_bytes) override;
  uint64_t GetEntropy() override;

 private:
  bool has_rdseed_;
};

}  // namespace yacl::crypto
