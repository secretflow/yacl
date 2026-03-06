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

#include <cstddef>
#include <exception>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/commitment.h"
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/sign_session.h"
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/sign_session_internal.h"

namespace tecdsa {
using namespace sign_internal;

bool SignSession::HandlePhase1CommitEnvelope(const Envelope& envelope) {
  if (envelope.to != kBroadcastPartyId) {
    Abort("sign phase1 commitment message must be broadcast");
    return false;
  }
  if (envelope.payload.size() != kCommitmentLen) {
    Abort("invalid sign phase1 commitment payload length");
    return false;
  }

  const bool inserted = seen_phase1_.insert(envelope.from).second;
  if (!inserted) {
    return true;
  }

  phase1_commitments_[envelope.from] = envelope.payload;
  Touch();
  MaybeAdvanceAfterPhase1();
  return true;
}

bool SignSession::HandlePhase2InitEnvelope(const Envelope& envelope) {
  if (envelope.to != self_id()) {
    Abort("sign phase2 initiator message must target receiver directly");
    return false;
  }

  try {
    size_t offset = 0;
    const uint32_t raw_type = ReadU32Be(envelope.payload, &offset);
    if (raw_type != static_cast<uint32_t>(MtaType::kTimesGamma) &&
        raw_type != static_cast<uint32_t>(MtaType::kTimesW)) {
      TECDSA_THROW_ARGUMENT("unknown phase2 MtA type");
    }
    const MtaType mta_type = static_cast<MtaType>(raw_type);

    const Bytes instance_id = ReadSizedField(
        envelope.payload, &offset, kMtaInstanceIdLen, "phase2 mta instance id");
    if (instance_id.size() != kMtaInstanceIdLen) {
      TECDSA_THROW_ARGUMENT("phase2 mta instance id has invalid length");
    }
    const BigInt c1 =
        ReadMpIntField(envelope.payload, &offset, kMaxMpIntEncodedLen,
                       "phase2 mta ciphertext c1");
    const A1RangeProof a1_proof = ReadA1RangeProof(envelope.payload, &offset);
    if (offset != envelope.payload.size()) {
      TECDSA_THROW_ARGUMENT("sign phase2 init payload has trailing bytes");
    }

    const auto sender_pk_it = all_paillier_public_.find(envelope.from);
    if (sender_pk_it == all_paillier_public_.end()) {
      TECDSA_THROW_ARGUMENT("missing Paillier public key for initiator");
    }
    const BigInt n = sender_pk_it->second.n;
    const BigInt n2 = n * n;
    if (c1 < 0 || c1 >= n2) {
      TECDSA_THROW_ARGUMENT("phase2 c1 is out of range");
    }
    const auto self_aux_it = all_aux_rsa_params_.find(self_id());
    if (self_aux_it == all_aux_rsa_params_.end()) {
      TECDSA_THROW_ARGUMENT("missing responder auxiliary parameters");
    }
    const MtaProofContext init_ctx{
        .session_id = session_id(),
        .initiator_id = envelope.from,
        .responder_id = self_id(),
        .mta_instance_id = instance_id,
    };
    if (!VerifyA1Range(init_ctx, n, self_aux_it->second, c1, a1_proof)) {
      TECDSA_THROW_ARGUMENT("phase2 A1 range proof verification failed");
    }

    const std::string request_key =
        MakeResponderRequestKey(envelope.from, static_cast<uint8_t>(raw_type));
    const std::string instance_key = BytesToKey(instance_id);
    const auto seen_request_it =
        phase2_responder_requests_seen_.find(request_key);
    if (seen_request_it != phase2_responder_requests_seen_.end()) {
      if (seen_request_it->second != instance_key) {
        TECDSA_THROW_ARGUMENT(
            "phase2 request instance mismatch for sender/type");
      }
      return true;
    }

    const Scalar witness =
        (mta_type == MtaType::kTimesGamma) ? local_gamma_i_ : local_w_i_;
    const BigInt y = RandomBelow(QPow5());
    const BigInt r_b = SampleZnStar(n);
    const BigInt gamma = n + BigInt(1);
    const BigInt c1_pow_x = PowMod(c1, witness.mp_value(), n2);
    const BigInt gamma_pow_y = PowMod(gamma, y, n2);
    const BigInt r_pow_n = PowMod(r_b, n, n2);
    const BigInt c2 = MulMod(MulMod(c1_pow_x, gamma_pow_y, n2), r_pow_n, n2);

    const Scalar responder_share(-y);
    if (mta_type == MtaType::kTimesGamma) {
      phase2_mta_responder_sum_ = phase2_mta_responder_sum_ + responder_share;
    } else {
      phase2_mtawc_responder_sum_ =
          phase2_mtawc_responder_sum_ + responder_share;
    }
    phase2_responder_requests_seen_.emplace(request_key, instance_key);

    const auto initiator_aux_it = all_aux_rsa_params_.find(envelope.from);
    if (initiator_aux_it == all_aux_rsa_params_.end()) {
      TECDSA_THROW_ARGUMENT("missing initiator auxiliary parameters");
    }
    const MtaProofContext response_ctx{
        .session_id = session_id(),
        .initiator_id = envelope.from,
        .responder_id = self_id(),
        .mta_instance_id = instance_id,
    };

    Bytes payload;
    AppendU32Be(raw_type, &payload);
    AppendSizedField(instance_id, &payload);
    AppendMpIntField(c2, &payload);
    if (mta_type == MtaType::kTimesGamma) {
      const A3MtAProof a3_proof =
          ProveA3MtA(response_ctx, n, initiator_aux_it->second, c1, c2,
                     witness.mp_value(), y, r_b);
      AppendA3MtAProof(a3_proof, &payload);
    } else {
      const auto statement_x_it = W_points_.find(self_id());
      if (statement_x_it == W_points_.end()) {
        TECDSA_THROW_ARGUMENT("missing responder W_j point for MtAwc proof");
      }
      const A2MtAwcProof a2_proof =
          ProveA2MtAwc(response_ctx, n, initiator_aux_it->second, c1, c2,
                       statement_x_it->second, witness.mp_value(), y, r_b);
      AppendA2MtAwcProof(a2_proof, &payload);
    }

    Envelope out;
    out.session_id = session_id();
    out.from = self_id();
    out.to = envelope.from;
    out.type = Phase2ResponseMessageType();
    out.payload = std::move(payload);
    phase2_outbox_.push_back(std::move(out));
  } catch (const std::exception& ex) {
    Abort(std::string("invalid sign phase2 initiator payload: ") + ex.what());
    return false;
  }

  seen_phase2_.insert(envelope.from);
  Touch();
  MaybeAdvanceAfterPhase2();
  return true;
}

bool SignSession::HandlePhase2ResponseEnvelope(const Envelope& envelope) {
  if (envelope.to != self_id()) {
    Abort("sign phase2 response message must target receiver directly");
    return false;
  }

  try {
    size_t offset = 0;
    const uint32_t raw_type = ReadU32Be(envelope.payload, &offset);
    if (raw_type != static_cast<uint32_t>(MtaType::kTimesGamma) &&
        raw_type != static_cast<uint32_t>(MtaType::kTimesW)) {
      TECDSA_THROW_ARGUMENT("unknown phase2 response MtA type");
    }
    const MtaType mta_type = static_cast<MtaType>(raw_type);

    const Bytes instance_id = ReadSizedField(
        envelope.payload, &offset, kMtaInstanceIdLen, "phase2 mta instance id");
    if (instance_id.size() != kMtaInstanceIdLen) {
      TECDSA_THROW_ARGUMENT("phase2 response instance id has invalid length");
    }
    const BigInt c2 =
        ReadMpIntField(envelope.payload, &offset, kMaxMpIntEncodedLen,
                       "phase2 mta ciphertext c2");
    std::optional<A3MtAProof> a3_proof;
    std::optional<A2MtAwcProof> a2_proof;
    if (mta_type == MtaType::kTimesGamma) {
      a3_proof = ReadA3MtAProof(envelope.payload, &offset);
    } else {
      a2_proof = ReadA2MtAwcProof(envelope.payload, &offset);
    }
    if (offset != envelope.payload.size()) {
      TECDSA_THROW_ARGUMENT("sign phase2 response payload has trailing bytes");
    }

    const std::string instance_key = BytesToKey(instance_id);
    const auto instance_it = phase2_initiator_instances_.find(instance_key);
    if (instance_it == phase2_initiator_instances_.end()) {
      TECDSA_THROW_ARGUMENT("unknown phase2 response instance id");
    }
    Phase2InitiatorInstance& instance = instance_it->second;
    if (instance.responder != envelope.from) {
      TECDSA_THROW_ARGUMENT("phase2 response sender mismatch");
    }
    if (instance.type != mta_type) {
      TECDSA_THROW_ARGUMENT("phase2 response type mismatch");
    }
    if (instance.response_received) {
      return true;
    }

    const auto self_pk_it = all_paillier_public_.find(self_id());
    if (self_pk_it == all_paillier_public_.end()) {
      TECDSA_THROW_ARGUMENT("missing self Paillier public key");
    }
    const BigInt n = self_pk_it->second.n;
    const BigInt n2 = n * n;
    if (c2 < 0 || c2 >= n2) {
      TECDSA_THROW_ARGUMENT("phase2 c2 is out of range");
    }
    const auto self_aux_it = all_aux_rsa_params_.find(self_id());
    if (self_aux_it == all_aux_rsa_params_.end()) {
      TECDSA_THROW_ARGUMENT("missing initiator auxiliary parameters");
    }
    const MtaProofContext response_ctx{
        .session_id = session_id(),
        .initiator_id = self_id(),
        .responder_id = envelope.from,
        .mta_instance_id = instance_id,
    };
    if (mta_type == MtaType::kTimesGamma) {
      if (!a3_proof.has_value()) {
        TECDSA_THROW_ARGUMENT("missing A3 proof in MtA response");
      }
      if (!VerifyA3MtA(response_ctx, n, self_aux_it->second, instance.c1, c2,
                       *a3_proof)) {
        TECDSA_THROW_ARGUMENT("phase2 A3 proof verification failed");
      }
    } else {
      if (!a2_proof.has_value()) {
        TECDSA_THROW_ARGUMENT("missing A2 proof in MtAwc response");
      }
      const auto statement_x_it = W_points_.find(envelope.from);
      if (statement_x_it == W_points_.end()) {
        TECDSA_THROW_ARGUMENT("missing W_j point for MtAwc response proof");
      }
      if (!VerifyA2MtAwc(response_ctx, n, self_aux_it->second, instance.c1, c2,
                         statement_x_it->second, *a2_proof)) {
        TECDSA_THROW_ARGUMENT("phase2 A2 proof verification failed");
      }
    }

    const BigInt decrypted = local_paillier_->DecryptBigInt(c2);
    const Scalar initiator_share(decrypted);
    if (mta_type == MtaType::kTimesGamma) {
      phase2_mta_initiator_sum_ = phase2_mta_initiator_sum_ + initiator_share;
    } else {
      phase2_mtawc_initiator_sum_ =
          phase2_mtawc_initiator_sum_ + initiator_share;
    }
    instance.response_received = true;
  } catch (const std::exception& ex) {
    Abort(std::string("invalid sign phase2 response payload: ") + ex.what());
    return false;
  }

  seen_phase2_.insert(envelope.from);
  Touch();
  MaybeAdvanceAfterPhase2();
  return true;
}

bool SignSession::HandlePhase3DeltaEnvelope(const Envelope& envelope) {
  if (envelope.to != kBroadcastPartyId) {
    Abort("sign phase3 delta message must be broadcast");
    return false;
  }

  const bool inserted = seen_phase3_.insert(envelope.from).second;
  if (!inserted) {
    return true;
  }

  try {
    size_t offset = 0;
    const Scalar delta_i = ReadScalar(envelope.payload, &offset);
    if (offset != envelope.payload.size()) {
      TECDSA_THROW_ARGUMENT("sign phase3 payload has trailing bytes");
    }

    phase3_delta_shares_[envelope.from] = delta_i;
  } catch (const std::exception& ex) {
    Abort(std::string("invalid sign phase3 payload: ") + ex.what());
    return false;
  }

  Touch();
  MaybeAdvanceAfterPhase3();
  return true;
}

bool SignSession::HandlePhase4OpenEnvelope(const Envelope& envelope) {
  if (envelope.to != kBroadcastPartyId) {
    Abort("sign phase4 open message must be broadcast");
    return false;
  }

  const bool inserted = seen_phase4_.insert(envelope.from).second;
  if (!inserted) {
    return true;
  }

  try {
    size_t offset = 0;
    const ECPoint gamma_i = ReadPoint(envelope.payload, &offset);
    const Bytes randomness =
        ReadSizedField(envelope.payload, &offset, kMaxOpenRandomnessLen,
                       "sign phase4 open randomness");
    const ECPoint proof_a = ReadPoint(envelope.payload, &offset);
    const Scalar proof_z = ReadScalar(envelope.payload, &offset);
    if (offset != envelope.payload.size()) {
      TECDSA_THROW_ARGUMENT("sign phase4 payload has trailing bytes");
    }

    const auto commitment_it = phase1_commitments_.find(envelope.from);
    if (commitment_it == phase1_commitments_.end()) {
      TECDSA_THROW_ARGUMENT("missing phase1 commitment for sender");
    }

    const Bytes gamma_bytes = gamma_i.ToCompressedBytes();
    if (!VerifyCommitment(kPhase1CommitDomain, gamma_bytes, randomness,
                          commitment_it->second)) {
      TECDSA_THROW_ARGUMENT("phase4 open does not match phase1 commitment");
    }

    const SchnorrProof gamma_proof{.a = proof_a, .z = proof_z};
    if (!VerifySchnorrProof(envelope.from, gamma_i, gamma_proof)) {
      TECDSA_THROW_ARGUMENT("phase4 gamma Schnorr proof verification failed");
    }

    phase4_open_data_[envelope.from] = Phase4OpenData{
        .gamma_i = gamma_i,
        .gamma_proof = gamma_proof,
        .randomness = randomness,
    };
  } catch (const std::exception& ex) {
    Abort(std::string("invalid sign phase4 payload: ") + ex.what());
    return false;
  }

  Touch();
  MaybeAdvanceAfterPhase4();
  return true;
}

bool SignSession::HandlePhase5ACommitEnvelope(const Envelope& envelope) {
  if (envelope.to != kBroadcastPartyId) {
    Abort("sign phase5A commitment message must be broadcast");
    return false;
  }
  if (envelope.payload.size() != kCommitmentLen) {
    Abort("invalid sign phase5A commitment payload length");
    return false;
  }

  const bool inserted = seen_phase5a_.insert(envelope.from).second;
  if (!inserted) {
    return true;
  }

  phase5a_commitments_[envelope.from] = envelope.payload;
  Touch();
  MaybeAdvanceAfterPhase5A();
  return true;
}

bool SignSession::HandlePhase5BOpenEnvelope(const Envelope& envelope) {
  if (envelope.to != kBroadcastPartyId) {
    Abort("sign phase5B open message must be broadcast");
    return false;
  }

  const bool inserted = seen_phase5b_.insert(envelope.from).second;
  if (!inserted) {
    return true;
  }

  try {
    size_t offset = 0;
    const ECPoint V_i = ReadPoint(envelope.payload, &offset);
    const ECPoint A_i = ReadPoint(envelope.payload, &offset);
    const Bytes randomness =
        ReadSizedField(envelope.payload, &offset, kMaxOpenRandomnessLen,
                       "sign phase5B open randomness");
    const ECPoint schnorr_a = ReadPoint(envelope.payload, &offset);
    const Scalar schnorr_z = ReadScalar(envelope.payload, &offset);
    const ECPoint relation_alpha = ReadPoint(envelope.payload, &offset);
    const Scalar relation_t = ReadScalar(envelope.payload, &offset);
    const Scalar relation_u = ReadScalar(envelope.payload, &offset);
    if (offset != envelope.payload.size()) {
      TECDSA_THROW_ARGUMENT("sign phase5B payload has trailing bytes");
    }

    const auto commitment_it = phase5a_commitments_.find(envelope.from);
    if (commitment_it == phase5a_commitments_.end()) {
      TECDSA_THROW_ARGUMENT("missing phase5A commitment for sender");
    }

    const Bytes commit_message = SerializePointPair(V_i, A_i);
    if (!VerifyCommitment(kPhase5ACommitDomain, commit_message, randomness,
                          commitment_it->second)) {
      TECDSA_THROW_ARGUMENT("phase5B open does not match phase5A commitment");
    }

    const SchnorrProof a_schnorr_proof{.a = schnorr_a, .z = schnorr_z};
    if (!VerifySchnorrProof(envelope.from, A_i, a_schnorr_proof)) {
      TECDSA_THROW_ARGUMENT("phase5B A_i Schnorr proof verification failed");
    }

    const VRelationProof v_relation_proof{
        .alpha = relation_alpha, .t = relation_t, .u = relation_u};
    if (!VerifyVRelationProof(envelope.from, R_, V_i, v_relation_proof)) {
      TECDSA_THROW_ARGUMENT("phase5B V relation proof verification failed");
    }

    phase5b_open_data_[envelope.from] = Phase5BOpenData{
        .V_i = V_i,
        .A_i = A_i,
        .a_schnorr_proof = a_schnorr_proof,
        .v_relation_proof = v_relation_proof,
        .randomness = randomness,
    };
  } catch (const std::exception& ex) {
    Abort(std::string("invalid sign phase5B payload: ") + ex.what());
    return false;
  }

  Touch();
  MaybeAdvanceAfterPhase5B();
  return true;
}

bool SignSession::HandlePhase5CCommitEnvelope(const Envelope& envelope) {
  if (envelope.to != kBroadcastPartyId) {
    Abort("sign phase5C commitment message must be broadcast");
    return false;
  }
  if (envelope.payload.size() != kCommitmentLen) {
    Abort("invalid sign phase5C commitment payload length");
    return false;
  }

  const bool inserted = seen_phase5c_.insert(envelope.from).second;
  if (!inserted) {
    return true;
  }

  phase5c_commitments_[envelope.from] = envelope.payload;
  Touch();
  MaybeAdvanceAfterPhase5C();
  return true;
}

bool SignSession::HandlePhase5DOpenEnvelope(const Envelope& envelope) {
  if (envelope.to != kBroadcastPartyId) {
    Abort("sign phase5D open message must be broadcast");
    return false;
  }

  const bool inserted = seen_phase5d_.insert(envelope.from).second;
  if (!inserted) {
    return true;
  }

  try {
    size_t offset = 0;
    const ECPoint U_i = ReadPoint(envelope.payload, &offset);
    const ECPoint T_i = ReadPoint(envelope.payload, &offset);
    const Bytes randomness =
        ReadSizedField(envelope.payload, &offset, kMaxOpenRandomnessLen,
                       "sign phase5D open randomness");
    if (offset != envelope.payload.size()) {
      TECDSA_THROW_ARGUMENT("sign phase5D payload has trailing bytes");
    }

    const auto commitment_it = phase5c_commitments_.find(envelope.from);
    if (commitment_it == phase5c_commitments_.end()) {
      TECDSA_THROW_ARGUMENT("missing phase5C commitment for sender");
    }

    const Bytes commit_message = SerializePointPair(U_i, T_i);
    if (!VerifyCommitment(kPhase5CCommitDomain, commit_message, randomness,
                          commitment_it->second)) {
      TECDSA_THROW_ARGUMENT("phase5D open does not match phase5C commitment");
    }

    phase5d_open_data_[envelope.from] =
        Phase5DOpenData{.U_i = U_i, .T_i = T_i, .randomness = randomness};
  } catch (const std::exception& ex) {
    Abort(std::string("invalid sign phase5D payload: ") + ex.what());
    return false;
  }

  Touch();
  MaybeAdvanceAfterPhase5D();
  return true;
}

bool SignSession::HandlePhase5ERevealEnvelope(const Envelope& envelope) {
  if (envelope.to != kBroadcastPartyId) {
    Abort("sign phase5E reveal message must be broadcast");
    return false;
  }

  const bool inserted = seen_phase5e_.insert(envelope.from).second;
  if (!inserted) {
    return true;
  }

  try {
    size_t offset = 0;
    const Scalar s_i = ReadScalar(envelope.payload, &offset);
    if (offset != envelope.payload.size()) {
      TECDSA_THROW_ARGUMENT("sign phase5E payload has trailing bytes");
    }

    phase5e_revealed_s_[envelope.from] = s_i;
  } catch (const std::exception& ex) {
    Abort(std::string("invalid sign phase5E payload: ") + ex.what());
    return false;
  }

  Touch();
  MaybeAdvanceAfterPhase5E();
  return true;
}

}  // namespace tecdsa
