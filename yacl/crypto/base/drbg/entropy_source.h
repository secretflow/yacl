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

#include "yacl/base/exception.h"

namespace yacl::crypto {

// EntropySource abstract class

enum class SecurityStrengthFlags { kStrength128, kStrength192, kStrength256 };

class IEntropySource {
 public:
  IEntropySource() = default;
  virtual ~IEntropySource() = default;

  virtual std::string GetEntropy(size_t entropy_bytes) = 0;
  virtual uint64_t GetEntropy() = 0;

  int GetStrengthBit(SecurityStrengthFlags security_strength) {
    switch (security_strength) {
      case SecurityStrengthFlags::kStrength256:
        return 256;
      case SecurityStrengthFlags::kStrength192:
        return 192;
      case SecurityStrengthFlags::kStrength128:
        return 128;
      default:
        YACL_THROW("Unknown security strength: {}",
                   static_cast<int>(security_strength));
    }
  }

  int GetEntropyBytes(SecurityStrengthFlags security_strength) {
    // key size + block size
    return GetStrengthBit(security_strength) / 8 + 16;
  }

  //
  int GetNonceBytes(SecurityStrengthFlags security_strength) {
    return GetStrengthBit(security_strength) / 16;
  }
};

}  // namespace yacl::crypto
