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

Envelope KeygenSession::BuildPhase3XiProofEnvelope() {
  if (IsTerminal()) {
    TECDSA_THROW_LOGIC("cannot build phase3 envelope for terminal keygen session");
  }
  if (phase_ != KeygenPhase::kPhase3) {
    TECDSA_THROW_LOGIC("BuildPhase3XiProofEnvelope must be called in keygen phase3");
  }
  if (!phase2_aggregates_ready_) {
    TECDSA_THROW_LOGIC("phase2 aggregates are not ready");
  }

  if (!local_phase3_payload_.has_value()) {
    if (result_.x_i.value() == 0) {
      Abort("aggregated local share is zero");
      TECDSA_THROW("aggregated local share is zero");
    }

    Phase3BroadcastData payload;
    payload.X_i = ECPoint::GeneratorMultiply(result_.x_i);
    payload.proof = BuildSchnorrProof(payload.X_i, result_.x_i);
    local_phase3_payload_ = payload;

    local_phase3_ready_ = true;
    phase3_broadcasts_[self_id()] = payload;
    result_.X_i = payload.X_i;
    result_.all_X_i[self_id()] = payload.X_i;
  }

  Bytes serialized;
  const Bytes square_free_proof_wire = EncodeSquareFreeProof(local_square_free_proof_);
  serialized.reserve(ki::kPointCompressedLen + ki::kPointCompressedLen + ki::kScalarLen +
                     4 + square_free_proof_wire.size());
  ki::AppendPoint(local_phase3_payload_->X_i, &serialized);
  ki::AppendPoint(local_phase3_payload_->proof.a, &serialized);
  ki::AppendScalar(local_phase3_payload_->proof.z, &serialized);
  ki::AppendSizedField(square_free_proof_wire, &serialized);
  result_.all_square_free_proofs[self_id()] = local_square_free_proof_;

  Envelope out;
  out.session_id = session_id();
  out.from = self_id();
  out.to = kBroadcastPartyId;
  out.type = MessageTypeForPhase(KeygenPhase::kPhase3);
  out.payload = std::move(serialized);

  MaybeAdvanceAfterPhase3();
  return out;
}

bool KeygenSession::HandlePhase3XiProofEnvelope(const Envelope& envelope) {
  if (envelope.to != kBroadcastPartyId) {
    Abort("keygen phase3 message must be broadcast");
    return false;
  }

  const bool inserted = seen_phase3_.insert(envelope.from).second;
  if (!inserted) {
    return true;
  }

  try {
    size_t offset = 0;
    const ECPoint X_i = ki::ReadPoint(envelope.payload, &offset);
    const ECPoint a = ki::ReadPoint(envelope.payload, &offset);
    const Scalar z = ki::ReadScalar(envelope.payload, &offset);

    const SchnorrProof proof{.a = a, .z = z};
    if (!VerifySchnorrProof(envelope.from, X_i, proof)) {
      TECDSA_THROW_ARGUMENT("schnorr proof verification failed");
    }

    const auto pk_it = result_.all_paillier_public.find(envelope.from);
    if (pk_it == result_.all_paillier_public.end()) {
      TECDSA_THROW_ARGUMENT("missing Paillier public key for phase3 sender");
    }

    SquareFreeProof square_free_proof;
    bool has_square_free_proof = false;
    if (offset < envelope.payload.size()) {
      const Bytes square_free_proof_wire = ki::ReadSizedField(
          envelope.payload, &offset, ki::kMaxProofFieldLen, "keygen phase3 square-free proof");
      if (!square_free_proof_wire.empty()) {
        square_free_proof = DecodeSquareFreeProof(square_free_proof_wire, ki::kMaxProofBlobLen);
        has_square_free_proof = true;
      }
    }
    if (offset != envelope.payload.size()) {
      TECDSA_THROW_ARGUMENT("keygen phase3 payload has trailing bytes");
    }

    if (strict_mode_) {
      const StrictProofVerifierContext context =
          ki::BuildStrictProofContext(session_id(), envelope.from);
      if (!has_square_free_proof) {
        TECDSA_THROW_ARGUMENT("missing square-free proof in strict mode");
      }
      if (expected_square_free_proof_profile_.scheme == StrictProofScheme::kUnknown) {
        expected_square_free_proof_profile_ = square_free_proof.metadata;
        result_.square_free_proof_profile = expected_square_free_proof_profile_;
      }
      if (!ki::StrictMetadataCompatible(expected_square_free_proof_profile_,
                                       square_free_proof.metadata)) {
        TECDSA_THROW_ARGUMENT("square-free proof metadata is not compatible with strict profile");
      }
      if (!VerifySquareFreeProofGmr98(pk_it->second.n, square_free_proof, context)) {
        TECDSA_THROW_ARGUMENT("square-free proof verification failed in strict mode");
      }
    } else if (has_square_free_proof &&
               !VerifySquareFreeProof(pk_it->second.n,
                                      square_free_proof,
                                      ki::BuildStrictProofContext(session_id(), envelope.from))) {
      TECDSA_THROW_ARGUMENT("square-free proof verification failed");
    }

    phase3_broadcasts_[envelope.from] = Phase3BroadcastData{.X_i = X_i, .proof = proof};
    result_.all_X_i[envelope.from] = X_i;
    if (has_square_free_proof) {
      result_.all_square_free_proofs[envelope.from] = std::move(square_free_proof);
    }
  } catch (const std::exception& ex) {
    Abort(std::string("invalid keygen phase3 payload: ") + ex.what());
    return false;
  }

  Touch();
  MaybeAdvanceAfterPhase3();
  return true;
}

void KeygenSession::MaybeAdvanceAfterPhase3() {
  if (phase_ != KeygenPhase::kPhase3) {
    return;
  }
  if (!local_phase3_ready_) {
    return;
  }
  if (seen_phase3_.size() != peers_.size()) {
    return;
  }
  if (phase3_broadcasts_.size() != participants_.size()) {
    return;
  }
  if (result_.all_X_i.size() != participants_.size()) {
    return;
  }
  if (strict_mode_) {
    if (result_.square_free_proof_profile.scheme == StrictProofScheme::kUnknown) {
      return;
    }
    if (result_.all_square_free_proofs.size() != participants_.size()) {
      return;
    }
    for (PartyIndex party : participants_) {
      const auto pk_it = result_.all_paillier_public.find(party);
      const auto square_it = result_.all_square_free_proofs.find(party);
      if (pk_it == result_.all_paillier_public.end() ||
          square_it == result_.all_square_free_proofs.end()) {
        return;
      }
      if (!ki::StrictMetadataCompatible(result_.square_free_proof_profile,
                                       square_it->second.metadata)) {
        return;
      }
      const StrictProofVerifierContext context =
          ki::BuildStrictProofContext(session_id(), party);
      if (!VerifySquareFreeProofGmr98(pk_it->second.n, square_it->second, context)) {
        return;
      }
    }
  }

  phase_ = KeygenPhase::kCompleted;
  Complete();
}

SchnorrProof KeygenSession::BuildSchnorrProof(const ECPoint& statement,
                                              const Scalar& witness) const {
  if (witness.value() == 0) {
    TECDSA_THROW_ARGUMENT("schnorr witness must be non-zero");
  }

  while (true) {
    const Scalar r = ki::RandomNonZeroScalar();
    const ECPoint a = ECPoint::GeneratorMultiply(r);
    const Scalar e = ki::BuildSchnorrChallenge(session_id(), self_id(), statement, a);
    const Scalar z = r + (e * witness);
    if (z.value() == 0) {
      continue;
    }
    return SchnorrProof{.a = a, .z = z};
  }
}

bool KeygenSession::VerifySchnorrProof(PartyIndex prover_id,
                                       const ECPoint& statement,
                                       const SchnorrProof& proof) const {
  if (proof.z.value() == 0) {
    return false;
  }

  try {
    const Scalar e = ki::BuildSchnorrChallenge(session_id(), prover_id, statement, proof.a);
    const ECPoint lhs = ECPoint::GeneratorMultiply(proof.z);

    ECPoint rhs = proof.a;
    if (e.value() != 0) {
      rhs = rhs.Add(statement.Mul(e));
    }
    return lhs == rhs;
  } catch (const std::exception&) {
    return false;
  }
}

}  // namespace tecdsa
