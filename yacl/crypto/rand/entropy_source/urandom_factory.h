// Copyright 2023 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <algorithm>
#include <memory>
#include <string>

#include "yacl/crypto/rand/entropy_source/entropy_source.h"

namespace yacl::crypto {

class UrandomEntropySource : public EntropySource {
 public:
  static std::unique_ptr<EntropySource> Create(
      const std::string &type, [[maybe_unused]] const SpiArgs &config) {
    // this entropy source should be used only if the CPU has rdseed support
    YACL_ENFORCE(absl::AsciiStrToLower(type) == "software" ||
                 absl::AsciiStrToLower(type) == "auto");
    return std::make_unique<UrandomEntropySource>();
  }

  // this checker would always return ture
  static bool Check(const std::string &type,
                    [[maybe_unused]] const SpiArgs &config) {
    return absl::AsciiStrToLower(type) == "software" ||
           absl::AsciiStrToLower(type) == "auto";
  }

  Buffer GetEntropy(uint32_t num_bytes) override;

  std::string Name() override { return "urandom entropy source"; }
};

}  // namespace yacl::crypto
