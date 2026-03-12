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

#include "yacl/crypto/experimental/threshold_ecdsa/crypto/commitment.h"

#include <stdexcept>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/hash.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/random.h"

namespace tecdsa {
namespace {

constexpr char kCommitPrefix[] = "GG2019/commit/v1";

void AppendU32Be(uint32_t value, Bytes* out) {
  out->push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
  out->push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
  out->push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
  out->push_back(static_cast<uint8_t>(value & 0xFF));
}

void AppendField(std::span<const uint8_t> field, Bytes* out) {
  if (field.size() > UINT32_MAX) {
    TECDSA_THROW_ARGUMENT("Commitment field exceeds uint32 length");
  }
  AppendU32Be(static_cast<uint32_t>(field.size()), out);
  out->insert(out->end(), field.begin(), field.end());
}

Bytes BuildCommitPreimage(const std::string& domain,
                          std::span<const uint8_t> message,
                          std::span<const uint8_t> randomness) {
  Bytes preimage;
  preimage.reserve(sizeof(kCommitPrefix) - 1 + domain.size() + message.size() +
                   randomness.size() + 12);

  const std::span<const uint8_t> prefix_bytes(
      reinterpret_cast<const uint8_t*>(kCommitPrefix),
      sizeof(kCommitPrefix) - 1);
  const std::span<const uint8_t> domain_bytes(
      reinterpret_cast<const uint8_t*>(domain.data()), domain.size());

  AppendField(prefix_bytes, &preimage);
  AppendField(domain_bytes, &preimage);
  AppendField(message, &preimage);
  AppendField(randomness, &preimage);
  return preimage;
}

}  // namespace

CommitmentResult CommitMessage(const std::string& domain,
                               std::span<const uint8_t> message,
                               size_t randomness_len) {
  CommitmentResult out;
  out.randomness = Csprng::RandomBytes(randomness_len);
  out.commitment = ComputeCommitment(domain, message, out.randomness);
  return out;
}

Bytes ComputeCommitment(const std::string& domain,
                        std::span<const uint8_t> message,
                        std::span<const uint8_t> randomness) {
  const Bytes preimage = BuildCommitPreimage(domain, message, randomness);
  return Sha256(preimage);
}

bool VerifyCommitment(const std::string& domain,
                      std::span<const uint8_t> message,
                      std::span<const uint8_t> randomness,
                      std::span<const uint8_t> commitment) {
  const Bytes expected = ComputeCommitment(domain, message, randomness);
  return std::equal(expected.begin(), expected.end(), commitment.begin(),
                    commitment.end());
}

}  // namespace tecdsa
