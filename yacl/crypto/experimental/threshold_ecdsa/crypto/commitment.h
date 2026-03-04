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
