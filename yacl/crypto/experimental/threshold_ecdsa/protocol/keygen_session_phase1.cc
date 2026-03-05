#include "yacl/crypto/experimental/threshold_ecdsa/protocol/keygen_session.h"

#include <cstddef>
#include <exception>
#include <stdexcept>
#include <string>
#include <utility>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/encoding.h"
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/keygen_session_internal.h"

namespace tecdsa {
namespace ki = keygen_internal;

Envelope KeygenSession::BuildPhase1CommitEnvelope() {
  if (IsTerminal()) {
    TECDSA_THROW_LOGIC("cannot build phase1 envelope for terminal keygen session");
  }
  if (phase_ != KeygenPhase::kPhase1) {
    TECDSA_THROW_LOGIC("BuildPhase1CommitEnvelope must be called in keygen phase1");
  }

  EnsureLocalPolynomialPrepared();
  EnsureLocalPaillierPrepared();
  EnsureLocalStrictProofArtifactsPrepared();
  phase1_commitments_[self_id()] = local_commitment_;
  result_.all_paillier_public[self_id()] = local_paillier_public_;
  result_.all_aux_rsa_params[self_id()] = local_aux_rsa_params_;
  if (!local_aux_param_proof_.blob.empty()) {
    result_.all_aux_param_proofs[self_id()] = local_aux_param_proof_;
  }
  if (strict_mode_) {
    strict_phase1_non_legacy_parties_.insert(self_id());
  }

  Bytes payload;
  payload.reserve(ki::kCommitmentLen + 4 + 4 * 512 + 4 + 64);
  payload.insert(payload.end(), local_commitment_.begin(), local_commitment_.end());
  ki::AppendMpIntField(local_paillier_->modulus_n_bigint(), &payload);
  ki::AppendMpIntField(local_aux_rsa_params_.n_tilde, &payload);
  ki::AppendMpIntField(local_aux_rsa_params_.h1, &payload);
  ki::AppendMpIntField(local_aux_rsa_params_.h2, &payload);
  const Bytes aux_param_proof_wire = EncodeAuxRsaParamProof(local_aux_param_proof_);
  ki::AppendSizedField(aux_param_proof_wire, &payload);

  Envelope out;
  out.session_id = session_id();
  out.from = self_id();
  out.to = kBroadcastPartyId;
  out.type = MessageTypeForPhase(KeygenPhase::kPhase1);
  out.payload = std::move(payload);
  return out;
}

void KeygenSession::EnsureLocalPaillierPrepared() {
  if (local_paillier_ != nullptr) {
    return;
  }

  for (size_t attempt = 0; attempt < ki::kMaxPaillierKeygenAttempts; ++attempt) {
    auto candidate = std::make_shared<PaillierProvider>(paillier_modulus_bits_);
    const BigInt candidate_n = candidate->modulus_n_bigint();
    if (candidate_n > ki::MinPaillierModulusQ8()) {
      local_paillier_ = std::move(candidate);
      local_paillier_public_ = PaillierPublicKey{.n = candidate_n};
      result_.local_paillier = local_paillier_;
      result_.all_paillier_public[self_id()] = local_paillier_public_;
      return;
    }
  }

  TECDSA_THROW("failed to generate Paillier modulus N > q^8");
}

void KeygenSession::EnsureLocalStrictProofArtifactsPrepared() {
  if (local_aux_rsa_params_.n_tilde > 0) {
    return;
  }

  if (local_paillier_ == nullptr) {
    TECDSA_THROW_LOGIC("local Paillier key must be prepared before strict artifacts");
  }

  const StrictProofVerifierContext context =
      ki::BuildStrictProofContext(session_id(), self_id());
  local_aux_rsa_params_ = GenerateAuxRsaParams(aux_rsa_modulus_bits_, self_id());
  local_square_free_proof_ = BuildSquareFreeProofGmr98(local_paillier_public_.n,
                                                        local_paillier_->private_lambda(),
                                                        context);
  if (require_aux_param_proof_) {
    local_aux_param_proof_ = BuildAuxRsaParamProof(local_aux_rsa_params_, context);
  } else {
    local_aux_param_proof_ = AuxRsaParamProof{};
  }

  if (expected_square_free_proof_profile_.scheme == StrictProofScheme::kUnknown) {
    expected_square_free_proof_profile_ = local_square_free_proof_.metadata;
  }
  if (require_aux_param_proof_ &&
      expected_aux_param_proof_profile_.scheme == StrictProofScheme::kUnknown) {
    expected_aux_param_proof_profile_ = local_aux_param_proof_.metadata;
  }
  result_.square_free_proof_profile = expected_square_free_proof_profile_;
  result_.aux_param_proof_profile =
      require_aux_param_proof_ ? expected_aux_param_proof_profile_ : ProofMetadata{};

  if (strict_mode_) {
    if (!ki::StrictMetadataCompatible(expected_square_free_proof_profile_,
                                      local_square_free_proof_.metadata)) {
      TECDSA_THROW("local square-free proof metadata does not match expected strict profile");
    }
    if (!VerifySquareFreeProofGmr98(local_paillier_public_.n, local_square_free_proof_, context)) {
      TECDSA_THROW("failed to self-verify local square-free proof");
    }
    if (require_aux_param_proof_) {
      if (!ki::StrictMetadataCompatible(expected_aux_param_proof_profile_,
                                        local_aux_param_proof_.metadata)) {
        TECDSA_THROW("local aux proof metadata does not match expected strict profile");
      }
      if (!VerifyAuxRsaParamProofStrict(local_aux_rsa_params_, local_aux_param_proof_, context)) {
        TECDSA_THROW("failed to self-verify local aux param proof");
      }
    }
  }
}

bool KeygenSession::HandlePhase1CommitEnvelope(const Envelope& envelope) {
  const bool inserted = seen_phase1_.insert(envelope.from).second;
  if (!inserted) {
    return true;
  }

  try {
    if (envelope.payload.size() < ki::kCommitmentLen + 4 + 1) {
      TECDSA_THROW_ARGUMENT("phase1 payload is too short");
    }

    size_t offset = 0;
    Bytes commitment(envelope.payload.begin(),
                     envelope.payload.begin() + static_cast<std::ptrdiff_t>(ki::kCommitmentLen));
    offset += ki::kCommitmentLen;

    const BigInt paillier_n = ki::ReadMpIntField(
        envelope.payload, &offset, ki::kMaxPaillierModulusFieldLen, "keygen phase1 Paillier modulus");

    const PaillierPublicKey pub{.n = paillier_n};
    ki::ValidatePaillierPublicKeyOrThrow(pub);

    AuxRsaParams aux_params;
    AuxRsaParamProof aux_param_proof;
    bool has_aux_param_proof = false;
    if (offset == envelope.payload.size()) {
      if (strict_mode_) {
        TECDSA_THROW_ARGUMENT("legacy phase1 payload shape is not allowed in strict mode");
      }
      aux_params = DeriveAuxRsaParamsFromModulus(pub.n, envelope.from);
    } else {
      aux_params.n_tilde = ki::ReadMpIntField(
          envelope.payload, &offset, ki::kMaxPaillierModulusFieldLen, "keygen phase1 aux Ntilde");
      aux_params.h1 = ki::ReadMpIntField(
          envelope.payload, &offset, ki::kMaxPaillierModulusFieldLen, "keygen phase1 aux h1");
      aux_params.h2 = ki::ReadMpIntField(
          envelope.payload, &offset, ki::kMaxPaillierModulusFieldLen, "keygen phase1 aux h2");
      if (!ValidateAuxRsaParams(aux_params)) {
        TECDSA_THROW_ARGUMENT("invalid aux RSA parameters");
      }
      const Bytes aux_param_proof_wire = ki::ReadSizedField(
          envelope.payload, &offset, ki::kMaxProofFieldLen, "keygen phase1 aux parameter proof");
      if (!aux_param_proof_wire.empty()) {
        aux_param_proof = DecodeAuxRsaParamProof(aux_param_proof_wire, ki::kMaxProofBlobLen);
        has_aux_param_proof = true;
      }
      if (offset != envelope.payload.size()) {
        TECDSA_THROW_ARGUMENT("keygen phase1 payload has trailing bytes");
      }
    }

    if (!ValidateAuxRsaParams(aux_params)) {
      TECDSA_THROW_ARGUMENT("invalid aux RSA parameters");
    }

    if (strict_mode_) {
      const StrictProofVerifierContext context =
          ki::BuildStrictProofContext(session_id(), envelope.from);
      if (require_aux_param_proof_ && !has_aux_param_proof) {
        TECDSA_THROW_ARGUMENT("missing aux parameter proof in strict mode");
      }
      if (has_aux_param_proof) {
        if (expected_aux_param_proof_profile_.scheme == StrictProofScheme::kUnknown) {
          expected_aux_param_proof_profile_ = aux_param_proof.metadata;
          result_.aux_param_proof_profile = expected_aux_param_proof_profile_;
        }
        if (!ki::StrictMetadataCompatible(expected_aux_param_proof_profile_,
                                         aux_param_proof.metadata)) {
          TECDSA_THROW_ARGUMENT("aux parameter proof metadata is not compatible with strict profile");
        }
        if (!VerifyAuxRsaParamProofStrict(aux_params, aux_param_proof, context)) {
          TECDSA_THROW_ARGUMENT("aux parameter proof verification failed in strict mode");
        }
      }
      strict_phase1_non_legacy_parties_.insert(envelope.from);
    } else if (has_aux_param_proof &&
               !VerifyAuxRsaParamProof(aux_params,
                                       aux_param_proof,
                                       ki::BuildStrictProofContext(session_id(), envelope.from))) {
      TECDSA_THROW_ARGUMENT("aux parameter proof verification failed");
    }

    phase1_commitments_[envelope.from] = std::move(commitment);
    result_.all_paillier_public[envelope.from] = pub;
    result_.all_aux_rsa_params[envelope.from] = std::move(aux_params);
    if (has_aux_param_proof) {
      result_.all_aux_param_proofs[envelope.from] = std::move(aux_param_proof);
    }
  } catch (const std::exception& ex) {
    Abort(std::string("invalid keygen phase1 payload: ") + ex.what());
    return false;
  }

  Touch();
  MaybeAdvanceAfterPhase1();
  return true;
}

void KeygenSession::MaybeAdvanceAfterPhase1() {
  if (phase_ != KeygenPhase::kPhase1) {
    return;
  }
  if (seen_phase1_.size() != peers_.size()) {
    return;
  }
  if (phase1_commitments_.size() != participants_.size()) {
    return;
  }
  if (result_.all_paillier_public.size() != participants_.size()) {
    return;
  }
  if (result_.all_aux_rsa_params.size() != participants_.size()) {
    return;
  }
  if (strict_mode_) {
    if (strict_phase1_non_legacy_parties_.size() != participants_.size()) {
      return;
    }
    if (require_aux_param_proof_) {
      if (result_.aux_param_proof_profile.scheme == StrictProofScheme::kUnknown) {
        return;
      }
      if (result_.all_aux_param_proofs.size() != participants_.size()) {
        return;
      }
      for (PartyIndex party : participants_) {
        if (!strict_phase1_non_legacy_parties_.contains(party)) {
          return;
        }
        const auto aux_it = result_.all_aux_rsa_params.find(party);
        const auto aux_pf_it = result_.all_aux_param_proofs.find(party);
        if (aux_it == result_.all_aux_rsa_params.end() ||
            aux_pf_it == result_.all_aux_param_proofs.end()) {
          return;
        }
        if (!ki::StrictMetadataCompatible(result_.aux_param_proof_profile,
                                         aux_pf_it->second.metadata)) {
          return;
        }
        const StrictProofVerifierContext context =
            ki::BuildStrictProofContext(session_id(), party);
        if (!VerifyAuxRsaParamProofStrict(aux_it->second, aux_pf_it->second, context)) {
          return;
        }
      }
    }
  }
  phase_ = KeygenPhase::kPhase2;
}

}  // namespace tecdsa
