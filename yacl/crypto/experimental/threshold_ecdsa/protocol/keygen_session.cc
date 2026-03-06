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

#include "yacl/crypto/experimental/threshold_ecdsa/protocol/keygen_session.h"

#include <string>
#include <utility>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"
#include "yacl/crypto/experimental/threshold_ecdsa/common/secure_zeroize.h"
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/keygen_session_internal.h"

namespace tecdsa {
namespace ki = keygen_internal;

KeygenSession::KeygenSession(KeygenSessionConfig cfg)
    : Session(std::move(cfg.session_id), cfg.self_id, cfg.timeout),
      participants_(std::move(cfg.participants)),
      threshold_(cfg.threshold),
      paillier_modulus_bits_(cfg.paillier_modulus_bits),
      aux_rsa_modulus_bits_(cfg.aux_rsa_modulus_bits),
      strict_mode_(cfg.strict_mode),
      require_aux_param_proof_(cfg.require_aux_param_proof),
      expected_square_free_proof_profile_(
          std::move(cfg.expected_square_free_proof_profile)),
      expected_aux_param_proof_profile_(
          std::move(cfg.expected_aux_param_proof_profile)),
      peers_(ki::BuildPeerSet(participants_, cfg.self_id)) {
  ki::ValidateParticipantsOrThrow(participants_, cfg.self_id);
  if (threshold_ >= participants_.size()) {
    TECDSA_THROW_ARGUMENT("threshold must be less than participant count");
  }
  if (paillier_modulus_bits_ < ki::kMinPaillierKeygenBits) {
    TECDSA_THROW_ARGUMENT("paillier_modulus_bits must be >= 2048");
  }
  if (aux_rsa_modulus_bits_ < ki::kMinAuxRsaKeygenBits) {
    TECDSA_THROW_ARGUMENT("aux_rsa_modulus_bits must be >= 2048");
  }
  if (strict_mode_) {
    if (expected_square_free_proof_profile_.scheme !=
            StrictProofScheme::kUnknown &&
        !IsStrictProofScheme(expected_square_free_proof_profile_.scheme)) {
      TECDSA_THROW_ARGUMENT(
          "strict keygen expected square-free profile must use strict scheme");
    }
    if (require_aux_param_proof_ &&
        expected_aux_param_proof_profile_.scheme !=
            StrictProofScheme::kUnknown &&
        !IsStrictProofScheme(expected_aux_param_proof_profile_.scheme)) {
      TECDSA_THROW_ARGUMENT(
          "strict keygen expected aux profile must use strict scheme");
    }
  }
  result_.keygen_session_id = session_id();
  result_.square_free_proof_profile = expected_square_free_proof_profile_;
  result_.aux_param_proof_profile = expected_aux_param_proof_profile_;
  result_.strict_mode = strict_mode_;
  result_.require_aux_param_proof = require_aux_param_proof_;
}

KeygenPhase KeygenSession::phase() const { return phase_; }

size_t KeygenSession::received_peer_count_in_phase() const {
  switch (phase_) {
    case KeygenPhase::kPhase1:
      return seen_phase1_.size();
    case KeygenPhase::kPhase2: {
      size_t complete = 0;
      for (PartyIndex peer : peers_) {
        if (seen_phase2_opens_.contains(peer) &&
            seen_phase2_shares_.contains(peer)) {
          ++complete;
        }
      }
      return complete;
    }
    case KeygenPhase::kPhase3:
      return seen_phase3_.size();
    case KeygenPhase::kCompleted:
      return peers_.size();
  }
  TECDSA_THROW_ARGUMENT("invalid keygen phase");
}

uint32_t KeygenSession::threshold() const { return threshold_; }

bool KeygenSession::PollTimeout(std::chrono::steady_clock::time_point now) {
  const bool timed_out = Session::PollTimeout(now);
  if (timed_out) {
    ClearSensitiveIntermediates();
  }
  return timed_out;
}

bool KeygenSession::HandleEnvelope(const Envelope& envelope) {
  if (PollTimeout()) {
    return false;
  }
  if (IsTerminal()) {
    return false;
  }

  std::string error;
  if (!ValidateSessionBinding(envelope.session_id, envelope.to, &error)) {
    return false;
  }

  if (!peers_.contains(envelope.from)) {
    return false;
  }

  switch (phase_) {
    case KeygenPhase::kPhase1:
      if (envelope.type != MessageTypeForPhase(KeygenPhase::kPhase1)) {
        Abort("unexpected envelope type for keygen phase1");
        return false;
      }
      return HandlePhase1CommitEnvelope(envelope);
    case KeygenPhase::kPhase2:
      if (envelope.type == MessageTypeForPhase(KeygenPhase::kPhase2)) {
        return HandlePhase2OpenEnvelope(envelope);
      }
      if (envelope.type == Phase2ShareMessageType()) {
        return HandlePhase2ShareEnvelope(envelope);
      }
      Abort("unexpected envelope type for keygen phase2");
      return false;
    case KeygenPhase::kPhase3:
      if (envelope.type != MessageTypeForPhase(KeygenPhase::kPhase3)) {
        Abort("unexpected envelope type for keygen phase3");
        return false;
      }
      return HandlePhase3XiProofEnvelope(envelope);
    case KeygenPhase::kCompleted:
      return false;
  }
  TECDSA_THROW_ARGUMENT("invalid keygen phase");
}

Envelope KeygenSession::MakePhaseBroadcastEnvelope(const Bytes& payload) const {
  if (IsTerminal()) {
    TECDSA_THROW_LOGIC("cannot create envelope for terminal session");
  }

  Envelope out;
  out.session_id = session_id();
  out.from = self_id();
  out.to = kBroadcastPartyId;
  out.type = MessageTypeForPhase(phase_);
  out.payload = payload;
  return out;
}

uint32_t KeygenSession::MessageTypeForPhase(KeygenPhase phase) {
  switch (phase) {
    case KeygenPhase::kPhase1:
      return static_cast<uint32_t>(KeygenMessageType::kPhase1);
    case KeygenPhase::kPhase2:
      return static_cast<uint32_t>(KeygenMessageType::kPhase2);
    case KeygenPhase::kPhase3:
      return static_cast<uint32_t>(KeygenMessageType::kPhase3);
    case KeygenPhase::kCompleted:
      return static_cast<uint32_t>(KeygenMessageType::kAbort);
  }
  TECDSA_THROW_ARGUMENT("invalid keygen phase");
}

uint32_t KeygenSession::Phase2ShareMessageType() {
  return static_cast<uint32_t>(KeygenMessageType::kPhase2Share);
}

void KeygenSession::ClearSensitiveIntermediates() {
  SecureZeroize(&local_poly_coefficients_);
  SecureZeroize(&local_shares_);
  SecureZeroize(&pending_phase2_shares_);
  SecureZeroize(&phase2_verified_shares_);
  SecureZeroize(&local_open_randomness_);
  SecureZeroize(&local_commitment_);

  if (local_phase3_payload_.has_value()) {
    SecureZeroize(&local_phase3_payload_->proof.z);
    local_phase3_payload_.reset();
  }

  for (auto& [party, open_data] : phase2_open_data_) {
    (void)party;
    SecureZeroize(&open_data.randomness);
  }
  phase2_open_data_.clear();

  for (auto& [party, phase3_data] : phase3_broadcasts_) {
    (void)party;
    SecureZeroize(&phase3_data.proof.z);
  }
  phase3_broadcasts_.clear();
}

void KeygenSession::Abort(const std::string& reason) {
  if (IsTerminal()) {
    return;
  }
  ClearSensitiveIntermediates();
  Session::Abort(reason);
}

void KeygenSession::Complete() {
  if (IsTerminal()) {
    return;
  }
  ClearSensitiveIntermediates();
  Session::Complete();
}

bool KeygenSession::HasResult() const {
  if (status() != SessionStatus::kCompleted ||
      phase_ != KeygenPhase::kCompleted || !phase2_aggregates_ready_ ||
      !local_phase3_ready_ || result_.all_X_i.size() != participants_.size() ||
      result_.all_paillier_public.size() != participants_.size() ||
      result_.all_aux_rsa_params.size() != participants_.size() ||
      result_.local_paillier == nullptr) {
    return false;
  }

  if (!strict_mode_) {
    return true;
  }

  if (result_.all_square_free_proofs.size() != participants_.size()) {
    return false;
  }
  if (result_.square_free_proof_profile.scheme == StrictProofScheme::kUnknown) {
    return false;
  }
  if (strict_phase1_non_legacy_parties_.size() != participants_.size()) {
    return false;
  }
  if (require_aux_param_proof_) {
    if (result_.all_aux_param_proofs.size() != participants_.size()) {
      return false;
    }
    if (result_.aux_param_proof_profile.scheme == StrictProofScheme::kUnknown) {
      return false;
    }
  }

  for (PartyIndex party : participants_) {
    if (!strict_phase1_non_legacy_parties_.contains(party)) {
      return false;
    }
    const auto pk_it = result_.all_paillier_public.find(party);
    const auto aux_it = result_.all_aux_rsa_params.find(party);
    const auto square_it = result_.all_square_free_proofs.find(party);
    if (pk_it == result_.all_paillier_public.end() ||
        aux_it == result_.all_aux_rsa_params.end() ||
        square_it == result_.all_square_free_proofs.end()) {
      return false;
    }
    if (!ki::StrictMetadataCompatible(result_.square_free_proof_profile,
                                      square_it->second.metadata)) {
      return false;
    }
    const StrictProofVerifierContext context =
        ki::BuildStrictProofContext(session_id(), party);
    if (!VerifySquareFreeProofGmr98(pk_it->second.n, square_it->second,
                                    context)) {
      return false;
    }
    if (require_aux_param_proof_) {
      const auto aux_pf_it = result_.all_aux_param_proofs.find(party);
      if (aux_pf_it == result_.all_aux_param_proofs.end()) {
        return false;
      }
      if (!ki::StrictMetadataCompatible(result_.aux_param_proof_profile,
                                        aux_pf_it->second.metadata)) {
        return false;
      }
      if (!VerifyAuxRsaParamProofStrict(aux_it->second, aux_pf_it->second,
                                        context)) {
        return false;
      }
    }
  }

  return true;
}

const KeygenResult& KeygenSession::result() const {
  if (!HasResult()) {
    TECDSA_THROW_LOGIC("keygen result is not ready");
  }
  return result_;
}

}  // namespace tecdsa
