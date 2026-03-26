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

#include <string>
#include <unordered_map>
#include <vector>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/messages.h"

namespace tecdsa::proto {

void ValidateParticipantsOrThrow(const std::vector<PartyIndex>& participants,
                                 PartyIndex self_id,
                                 const char* context_name);

std::vector<PartyIndex> BuildPeers(const std::vector<PartyIndex>& participants,
                                   PartyIndex self_id);

template <typename T>
void RequireExactlyPeers(const PeerMap<T>& messages,
                         const std::vector<PartyIndex>& participants,
                         PartyIndex self_id, const char* field_name) {
  size_t expected = 0;
  for (PartyIndex party : participants) {
    if (party != self_id) {
      ++expected;
    }
  }
  if (messages.size() != expected) {
    TECDSA_THROW_ARGUMENT(std::string(field_name) +
                          " must contain exactly one entry per peer");
  }
  for (PartyIndex party : participants) {
    if (party == self_id) {
      continue;
    }
    if (!messages.contains(party)) {
      TECDSA_THROW_ARGUMENT(std::string(field_name) +
                            " is missing a peer message");
    }
  }
}

Scalar RandomNonZeroScalar();
Scalar EvaluatePolynomialAt(const std::vector<Scalar>& coefficients,
                            PartyIndex party_id);

StrictProofVerifierContext BuildProofContext(const Bytes& session_id,
                                             PartyIndex prover_id);

SchnorrProof BuildSchnorrProof(const Bytes& session_id, PartyIndex prover_id,
                               const ECPoint& statement,
                               const Scalar& witness);
bool VerifySchnorrProof(const Bytes& session_id, PartyIndex prover_id,
                        const ECPoint& statement, const SchnorrProof& proof);

const BigInt& MinPaillierModulusQ8();
void ValidatePaillierPublicKeyOrThrow(const PaillierPublicKey& pub);

std::unordered_map<PartyIndex, Scalar> ComputeLagrangeAtZero(
    const std::vector<PartyIndex>& participants);

ECPoint SumPointsOrThrow(const std::vector<ECPoint>& points);
Scalar XCoordinateModQ(const ECPoint& point);
bool IsHighScalar(const Scalar& scalar);

}  // namespace tecdsa::proto
