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

#include <exception>
#include <optional>
#include <span>
#include <string>

#include "yacl/crypto/experimental/threshold_signatures/common/errors.h"
#include "yacl/crypto/experimental/threshold_signatures/ecdsa/sign/sign.h"

namespace tecdsa::ecdsa::sign::internal {

inline constexpr size_t kCommitmentLen = 32;
inline constexpr char kPhase1CommitDomain[] = "GG2019/sign/phase1";
inline constexpr char kPhase5ACommitDomain[] = "GG2019/sign/phase5A";
inline constexpr char kPhase5CCommitDomain[] = "GG2019/sign/phase5C";

inline void ValidateCommitmentOrThrow(const Bytes& commitment,
                                      const char* field_name) {
  if (commitment.size() != kCommitmentLen) {
    TECDSA_THROW_ARGUMENT(std::string(field_name) +
                          " must be exactly 32 bytes");
  }
}

inline std::optional<Scalar> InvertScalar(const Scalar& scalar) {
  if (scalar.value() == 0) {
    return std::nullopt;
  }
  try {
    return scalar.InverseModQ();
  } catch (const std::exception&) {
    return std::nullopt;
  }
}

template <typename Msg>
void StoreCommitments(const PeerMap<Msg>& messages,
                      std::span<const PartyIndex> peers,
                      PeerMap<Bytes>* commitments, const char* field_name) {
  for (PartyIndex peer : peers) {
    const Bytes& commitment = messages.at(peer).commitment;
    ValidateCommitmentOrThrow(commitment, field_name);
    (*commitments)[peer] = commitment;
  }
}

}  // namespace tecdsa::ecdsa::sign::internal
