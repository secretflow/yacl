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

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "yacl/crypto/experimental/threshold_ecdsa/crypto/ec_point.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/paillier.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/scalar.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/strict_proofs.h"
#include "yacl/crypto/experimental/threshold_ecdsa/net/envelope.h"
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/session.h"

namespace tecdsa {

enum class KeygenPhase : uint32_t {
  kPhase1 = 1,
  kPhase2 = 2,
  kPhase3 = 3,
  kCompleted = 4,
};

enum class KeygenMessageType : uint32_t {
  kPhase1 = 1001,
  kPhase2 = 1002,
  kPhase3 = 1003,
  kPhase2Share = 1004,
  kAbort = 1099,
};

struct KeygenSessionConfig {
  Bytes session_id;
  PartyIndex self_id = 0;
  std::vector<PartyIndex> participants;
  uint32_t threshold = 1;
  uint32_t paillier_modulus_bits = 2048;
  uint32_t aux_rsa_modulus_bits = 2048;
  bool strict_mode = true;
  bool require_aux_param_proof = false;
  ProofMetadata expected_square_free_proof_profile;
  ProofMetadata expected_aux_param_proof_profile;
  std::chrono::milliseconds timeout = std::chrono::seconds(30);
};

struct SchnorrProof {
  ECPoint a;
  Scalar z;
};

struct KeygenResult {
  Bytes keygen_session_id;
  Scalar x_i;
  ECPoint X_i;
  ECPoint y;
  std::unordered_map<PartyIndex, ECPoint> all_X_i;
  std::shared_ptr<PaillierProvider> local_paillier;
  std::unordered_map<PartyIndex, PaillierPublicKey> all_paillier_public;
  std::unordered_map<PartyIndex, AuxRsaParams> all_aux_rsa_params;
  std::unordered_map<PartyIndex, SquareFreeProof> all_square_free_proofs;
  std::unordered_map<PartyIndex, AuxRsaParamProof> all_aux_param_proofs;
  ProofMetadata square_free_proof_profile;
  ProofMetadata aux_param_proof_profile;
  bool strict_mode = true;
  bool require_aux_param_proof = false;
};

class KeygenSession : public Session {
 public:
  explicit KeygenSession(KeygenSessionConfig cfg);

  KeygenPhase phase() const;
  size_t received_peer_count_in_phase() const;
  uint32_t threshold() const;

  bool HandleEnvelope(const Envelope& envelope);
  Envelope MakePhaseBroadcastEnvelope(const Bytes& payload) const;
  Envelope BuildPhase1CommitEnvelope();
  std::vector<Envelope> BuildPhase2OpenAndShareEnvelopes();
  Envelope BuildPhase3XiProofEnvelope();

  bool HasResult() const;
  const KeygenResult& result() const;
  bool PollTimeout(std::chrono::steady_clock::time_point now =
                       std::chrono::steady_clock::now());

  static uint32_t MessageTypeForPhase(KeygenPhase phase);
  static uint32_t Phase2ShareMessageType();

 private:
  struct Phase2OpenData {
    ECPoint y_i;
    Bytes randomness;
    std::vector<ECPoint> commitments;
  };

  struct Phase3BroadcastData {
    ECPoint X_i;
    SchnorrProof proof;
  };

  void EnsureLocalPolynomialPrepared();
  bool HandlePhase1CommitEnvelope(const Envelope& envelope);
  bool HandlePhase2OpenEnvelope(const Envelope& envelope);
  bool HandlePhase2ShareEnvelope(const Envelope& envelope);
  bool HandlePhase3XiProofEnvelope(const Envelope& envelope);

  bool VerifyDealerShareForSelf(PartyIndex dealer, const Scalar& share) const;
  void EnsureLocalPaillierPrepared();
  void EnsureLocalStrictProofArtifactsPrepared();
  void MaybeAdvanceAfterPhase1();
  void MaybeAdvanceAfterPhase2();
  void MaybeAdvanceAfterPhase3();
  void ComputePhase2Aggregates();
  void ClearSensitiveIntermediates();
  void Abort(const std::string& reason);
  void Complete();
  SchnorrProof BuildSchnorrProof(const ECPoint& statement,
                                 const Scalar& witness) const;
  bool VerifySchnorrProof(PartyIndex prover_id, const ECPoint& statement,
                          const SchnorrProof& proof) const;

  std::vector<PartyIndex> participants_;
  uint32_t threshold_ = 1;
  uint32_t paillier_modulus_bits_ = 2048;
  uint32_t aux_rsa_modulus_bits_ = 2048;
  bool strict_mode_ = true;
  bool require_aux_param_proof_ = false;
  ProofMetadata expected_square_free_proof_profile_;
  ProofMetadata expected_aux_param_proof_profile_;
  std::unordered_set<PartyIndex> peers_;

  std::unordered_set<PartyIndex> seen_phase1_;
  std::unordered_set<PartyIndex> seen_phase2_opens_;
  std::unordered_set<PartyIndex> seen_phase2_shares_;
  std::unordered_set<PartyIndex> seen_phase3_;
  std::unordered_set<PartyIndex> strict_phase1_non_legacy_parties_;

  bool local_phase2_ready_ = false;
  bool local_phase3_ready_ = false;

  std::vector<Scalar> local_poly_coefficients_;
  std::unordered_map<PartyIndex, Scalar> local_shares_;
  std::shared_ptr<PaillierProvider> local_paillier_;
  PaillierPublicKey local_paillier_public_;
  AuxRsaParams local_aux_rsa_params_;
  SquareFreeProof local_square_free_proof_;
  AuxRsaParamProof local_aux_param_proof_;
  ECPoint local_y_i_;
  Bytes local_commitment_;
  Bytes local_open_randomness_;
  std::vector<ECPoint> local_vss_commitments_;
  std::optional<Phase3BroadcastData> local_phase3_payload_;

  std::unordered_map<PartyIndex, Bytes> phase1_commitments_;
  std::unordered_map<PartyIndex, Phase2OpenData> phase2_open_data_;
  std::unordered_map<PartyIndex, Scalar> pending_phase2_shares_;
  std::unordered_map<PartyIndex, Scalar> phase2_verified_shares_;
  std::unordered_map<PartyIndex, Phase3BroadcastData> phase3_broadcasts_;

  bool phase2_aggregates_ready_ = false;
  KeygenResult result_;
  KeygenPhase phase_ = KeygenPhase::kPhase1;
};

}  // namespace tecdsa
