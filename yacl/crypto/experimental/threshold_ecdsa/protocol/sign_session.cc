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

#include "yacl/crypto/experimental/threshold_ecdsa/protocol/sign_session.h"

#include <algorithm>
#include <string>
#include <utility>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/sign_session_internal.h"

namespace tecdsa {
using namespace sign_internal;

SignSession::SignSession(SignSessionConfig cfg)
    : Session(std::move(cfg.session_id), cfg.self_id, cfg.timeout),
      participants_(std::move(cfg.participants)),
      peers_(BuildPeerSet(participants_, cfg.self_id)),
      all_X_i_(std::move(cfg.all_X_i)),
      all_paillier_public_(std::move(cfg.all_paillier_public)),
      all_aux_rsa_params_(std::move(cfg.all_aux_rsa_params)),
      all_square_free_proofs_(std::move(cfg.all_square_free_proofs)),
      all_aux_param_proofs_(std::move(cfg.all_aux_param_proofs)),
      expected_square_free_proof_profile_(
          std::move(cfg.square_free_proof_profile)),
      expected_aux_param_proof_profile_(std::move(cfg.aux_param_proof_profile)),
      local_paillier_(std::move(cfg.local_paillier)),
      strict_mode_(cfg.strict_mode),
      require_aux_param_proof_(cfg.require_aux_param_proof),
      local_x_i_(cfg.x_i),
      public_key_y_(cfg.y),
      msg32_(std::move(cfg.msg32)),
      fixed_k_i_(cfg.fixed_k_i),
      fixed_gamma_i_(cfg.fixed_gamma_i) {
  ValidateParticipantsOrThrow(participants_, cfg.self_id);
  const Bytes keygen_session_id = std::move(cfg.keygen_session_id);

  if (msg32_.size() != 32) {
    TECDSA_THROW_ARGUMENT("msg32 must be exactly 32 bytes for SignSession");
  }
  if (local_x_i_.value() == 0) {
    TECDSA_THROW_ARGUMENT("local x_i share must be non-zero");
  }
  if (local_paillier_ == nullptr) {
    TECDSA_THROW_ARGUMENT("local Paillier provider must be present");
  }
  if (strict_mode_) {
    if (expected_square_free_proof_profile_.scheme !=
            StrictProofScheme::kUnknown &&
        !IsStrictProofScheme(expected_square_free_proof_profile_.scheme)) {
      TECDSA_THROW_ARGUMENT(
          "strict sign expected square-free profile must use strict scheme");
    }
    if (expected_aux_param_proof_profile_.scheme !=
            StrictProofScheme::kUnknown &&
        !IsStrictProofScheme(expected_aux_param_proof_profile_.scheme)) {
      TECDSA_THROW_ARGUMENT(
          "strict sign expected aux profile must use strict scheme");
    }
  }

  for (PartyIndex party : participants_) {
    if (!all_X_i_.contains(party)) {
      TECDSA_THROW_ARGUMENT("all_X_i is missing participant public share");
    }
    const auto paillier_it = all_paillier_public_.find(party);
    if (paillier_it == all_paillier_public_.end()) {
      TECDSA_THROW_ARGUMENT("all_paillier_public is missing participant key");
    }
    if (paillier_it->second.n <= MinPaillierModulusQ8()) {
      TECDSA_THROW_ARGUMENT("Paillier modulus must satisfy N > q^8");
    }

    const auto aux_it = all_aux_rsa_params_.find(party);
    if (aux_it == all_aux_rsa_params_.end()) {
      TECDSA_THROW_ARGUMENT("all_aux_rsa_params is missing participant params");
    }
    ValidateAuxRsaParamsOrThrow(aux_it->second);

    const auto square_it = all_square_free_proofs_.find(party);
    const bool has_square_proof = square_it != all_square_free_proofs_.end() &&
                                  !square_it->second.blob.empty();
    if (strict_mode_ && !has_square_proof) {
      TECDSA_THROW_ARGUMENT(
          "strict mode requires square-free proof for each participant");
    }
    if (has_square_proof) {
      const StrictProofVerifierContext context =
          BuildKeygenProofContext(keygen_session_id, party);
      if (strict_mode_) {
        if (expected_square_free_proof_profile_.scheme ==
            StrictProofScheme::kUnknown) {
          expected_square_free_proof_profile_ = square_it->second.metadata;
        }
        if (!StrictMetadataCompatible(expected_square_free_proof_profile_,
                                      square_it->second.metadata)) {
          TECDSA_THROW_ARGUMENT(
              "square-free proof metadata is not compatible with strict "
              "profile");
        }
        if (!VerifySquareFreeProofGmr98(paillier_it->second.n,
                                        square_it->second, context)) {
          TECDSA_THROW_ARGUMENT("square-free proof verification failed");
        }
      } else if (!VerifySquareFreeProof(paillier_it->second.n,
                                        square_it->second, context)) {
        TECDSA_THROW_ARGUMENT("square-free proof verification failed");
      }
    }

    const auto aux_pf_it = all_aux_param_proofs_.find(party);
    const bool has_aux_proof = aux_pf_it != all_aux_param_proofs_.end() &&
                               !aux_pf_it->second.blob.empty();
    if (strict_mode_ && require_aux_param_proof_ && !has_aux_proof) {
      TECDSA_THROW_ARGUMENT(
          "strict mode requires aux parameter proof for each participant");
    }
    if (has_aux_proof) {
      const StrictProofVerifierContext context =
          BuildKeygenProofContext(keygen_session_id, party);
      if (strict_mode_) {
        if (expected_aux_param_proof_profile_.scheme ==
            StrictProofScheme::kUnknown) {
          expected_aux_param_proof_profile_ = aux_pf_it->second.metadata;
        }
        if (!StrictMetadataCompatible(expected_aux_param_proof_profile_,
                                      aux_pf_it->second.metadata)) {
          TECDSA_THROW_ARGUMENT(
              "aux proof metadata is not compatible with strict profile");
        }
        if (!VerifyAuxRsaParamProofStrict(aux_it->second, aux_pf_it->second,
                                          context)) {
          TECDSA_THROW_ARGUMENT("aux parameter proof verification failed");
        }
      } else if (!VerifyAuxRsaParamProof(aux_it->second, aux_pf_it->second,
                                         context)) {
        TECDSA_THROW_ARGUMENT("aux parameter proof verification failed");
      }
    }
  }
  const auto self_pk_it = all_paillier_public_.find(self_id());
  if (self_pk_it == all_paillier_public_.end()) {
    TECDSA_THROW_ARGUMENT("missing self Paillier public key");
  }
  if (self_pk_it->second.n != local_paillier_->modulus_n()) {
    TECDSA_THROW_ARGUMENT(
        "self Paillier public key does not match local provider");
  }

  message_scalar_ = Scalar::FromBigEndianModQ(msg32_);
  PrepareResharedSigningShares();
}

SignPhase SignSession::phase() const { return phase_; }

SignPhase5Stage SignSession::phase5_stage() const { return phase5_stage_; }

size_t SignSession::received_peer_count_in_phase() const {
  switch (phase_) {
    case SignPhase::kPhase1:
      return seen_phase1_.size();
    case SignPhase::kPhase2:
      return std::min(phase2_initiator_instances_.size(),
                      phase2_responder_requests_seen_.size()) /
             2;
    case SignPhase::kPhase3:
      return seen_phase3_.size();
    case SignPhase::kPhase4:
      return seen_phase4_.size();
    case SignPhase::kPhase5:
      switch (phase5_stage_) {
        case SignPhase5Stage::kPhase5A:
          return seen_phase5a_.size();
        case SignPhase5Stage::kPhase5B:
          return seen_phase5b_.size();
        case SignPhase5Stage::kPhase5C:
          return seen_phase5c_.size();
        case SignPhase5Stage::kPhase5D:
          return seen_phase5d_.size();
        case SignPhase5Stage::kPhase5E:
          return seen_phase5e_.size();
        case SignPhase5Stage::kCompleted:
          return peers_.size();
      }
      TECDSA_THROW_ARGUMENT("invalid phase5 stage");
    case SignPhase::kCompleted:
      return peers_.size();
  }
  TECDSA_THROW_ARGUMENT("invalid sign phase");
}

}  // namespace tecdsa
