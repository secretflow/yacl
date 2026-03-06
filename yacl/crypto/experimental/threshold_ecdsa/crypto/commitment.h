// Copyright 2026 Ant Group Co., Ltd.
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

#include <span>
#include <string>

#include "yacl/crypto/experimental/threshold_ecdsa/common/bytes.h"

namespace tecdsa {

struct CommitmentResult {
  Bytes commitment;
  Bytes randomness;
};

CommitmentResult CommitMessage(const std::string& domain,
                               std::span<const uint8_t> message,
                               size_t randomness_len = 32);

Bytes ComputeCommitment(const std::string& domain,
                        std::span<const uint8_t> message,
                        std::span<const uint8_t> randomness);

bool VerifyCommitment(const std::string& domain,
                      std::span<const uint8_t> message,
                      std::span<const uint8_t> randomness,
                      std::span<const uint8_t> commitment);

}  // namespace tecdsa
