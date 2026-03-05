#include "yacl/crypto/experimental/threshold_ecdsa/protocol/sign_session.h"

#include <cstddef>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"
#include "yacl/crypto/experimental/threshold_ecdsa/common/secure_zeroize.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/commitment.h"
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/sign_session_internal.h"

namespace tecdsa {
using namespace sign_internal;

Envelope SignSession::BuildPhase1CommitEnvelope() {
  if (IsTerminal()) {
    TECDSA_THROW_LOGIC("cannot build phase1 envelope for terminal sign session");
  }
  if (phase_ != SignPhase::kPhase1) {
    TECDSA_THROW_LOGIC("BuildPhase1CommitEnvelope must be called in sign phase1");
  }

  PreparePhase1SecretsIfNeeded();

  local_phase1_ready_ = true;
  phase1_commitments_[self_id()] = local_phase1_commitment_;

  Envelope out;
  out.session_id = session_id();
  out.from = self_id();
  out.to = kBroadcastPartyId;
  out.type = MessageTypeForPhase(SignPhase::kPhase1);
  out.payload = local_phase1_commitment_;

  MaybeAdvanceAfterPhase1();
  return out;
}

std::vector<Envelope> SignSession::BuildPhase2MtaEnvelopes() {
  if (IsTerminal()) {
    TECDSA_THROW_LOGIC("cannot build phase2 envelopes for terminal sign session");
  }
  if (phase_ != SignPhase::kPhase2) {
    TECDSA_THROW_LOGIC("BuildPhase2MtaEnvelopes must be called in sign phase2");
  }

  InitializePhase2InstancesIfNeeded();

  std::vector<Envelope> out;
  out.swap(phase2_outbox_);

  MaybeAdvanceAfterPhase2();
  return out;
}

Envelope SignSession::BuildPhase3DeltaEnvelope() {
  if (IsTerminal()) {
    TECDSA_THROW_LOGIC("cannot build phase3 envelope for terminal sign session");
  }
  if (phase_ != SignPhase::kPhase3) {
    TECDSA_THROW_LOGIC("BuildPhase3DeltaEnvelope must be called in sign phase3");
  }

  local_phase3_ready_ = true;
  phase3_delta_shares_[self_id()] = local_delta_i_;

  Envelope out;
  out.session_id = session_id();
  out.from = self_id();
  out.to = kBroadcastPartyId;
  out.type = MessageTypeForPhase(SignPhase::kPhase3);
  AppendScalar(local_delta_i_, &out.payload);

  MaybeAdvanceAfterPhase3();
  return out;
}

Envelope SignSession::BuildPhase4OpenGammaEnvelope() {
  if (IsTerminal()) {
    TECDSA_THROW_LOGIC("cannot build phase4 envelope for terminal sign session");
  }
  if (phase_ != SignPhase::kPhase4) {
    TECDSA_THROW_LOGIC("BuildPhase4OpenGammaEnvelope must be called in sign phase4");
  }

  PreparePhase1SecretsIfNeeded();
  const SchnorrProof gamma_proof = BuildSchnorrProof(local_Gamma_i_, local_gamma_i_);

  local_phase4_ready_ = true;
  phase4_open_data_[self_id()] = Phase4OpenData{
      .gamma_i = local_Gamma_i_,
      .gamma_proof = gamma_proof,
      .randomness = local_phase1_randomness_,
  };

  Bytes payload;
  payload.reserve(kPointCompressedLen + 4 + local_phase1_randomness_.size() + kPointCompressedLen + kScalarLen);
  AppendPoint(local_Gamma_i_, &payload);
  AppendSizedField(local_phase1_randomness_, &payload);
  AppendPoint(gamma_proof.a, &payload);
  AppendScalar(gamma_proof.z, &payload);

  Envelope out;
  out.session_id = session_id();
  out.from = self_id();
  out.to = kBroadcastPartyId;
  out.type = MessageTypeForPhase(SignPhase::kPhase4);
  out.payload = std::move(payload);

  MaybeAdvanceAfterPhase4();
  return out;
}

Envelope SignSession::BuildPhase5ACommitEnvelope() {
  if (IsTerminal()) {
    TECDSA_THROW_LOGIC("cannot build phase5A envelope for terminal sign session");
  }
  if (phase_ != SignPhase::kPhase5 || phase5_stage_ != SignPhase5Stage::kPhase5A) {
    TECDSA_THROW_LOGIC("BuildPhase5ACommitEnvelope must be called in sign phase5A");
  }

  local_s_i_ = (message_scalar_ * local_k_i_) + (r_ * local_sigma_i_);
  local_l_i_ = RandomNonZeroScalar();
  local_rho_i_ = RandomNonZeroScalar();

  ECPoint V_i = ECPoint::GeneratorMultiply(local_l_i_);
  if (local_s_i_.value() != 0) {
    V_i = V_i.Add(R_.Mul(local_s_i_));
  }
  local_V_i_ = V_i;
  local_A_i_ = ECPoint::GeneratorMultiply(local_rho_i_);

  const Bytes commit_message = SerializePointPair(local_V_i_, local_A_i_);
  const CommitmentResult commitment = CommitMessage(kPhase5ACommitDomain, commit_message);

  local_phase5a_randomness_ = commitment.randomness;
  local_phase5a_commitment_ = commitment.commitment;

  local_phase5a_ready_ = true;
  phase5a_commitments_[self_id()] = local_phase5a_commitment_;

  Envelope out;
  out.session_id = session_id();
  out.from = self_id();
  out.to = kBroadcastPartyId;
  out.type = MessageTypeForPhase5Stage(SignPhase5Stage::kPhase5A);
  out.payload = local_phase5a_commitment_;

  MaybeAdvanceAfterPhase5A();
  return out;
}

Envelope SignSession::BuildPhase5BOpenEnvelope() {
  if (IsTerminal()) {
    TECDSA_THROW_LOGIC("cannot build phase5B envelope for terminal sign session");
  }
  if (phase_ != SignPhase::kPhase5 || phase5_stage_ != SignPhase5Stage::kPhase5B) {
    TECDSA_THROW_LOGIC("BuildPhase5BOpenEnvelope must be called in sign phase5B");
  }

  const SchnorrProof a_schnorr_proof = BuildSchnorrProof(local_A_i_, local_rho_i_);
  const VRelationProof v_relation_proof =
      BuildVRelationProof(R_, local_V_i_, local_s_i_, local_l_i_);

  local_phase5b_ready_ = true;
  phase5b_open_data_[self_id()] = Phase5BOpenData{
      .V_i = local_V_i_,
      .A_i = local_A_i_,
      .a_schnorr_proof = a_schnorr_proof,
      .v_relation_proof = v_relation_proof,
      .randomness = local_phase5a_randomness_,
  };

  Bytes payload;
  payload.reserve(kPointCompressedLen * 4 + kScalarLen * 3 + 4 + local_phase5a_randomness_.size());
  AppendPoint(local_V_i_, &payload);
  AppendPoint(local_A_i_, &payload);
  AppendSizedField(local_phase5a_randomness_, &payload);
  AppendPoint(a_schnorr_proof.a, &payload);
  AppendScalar(a_schnorr_proof.z, &payload);
  AppendPoint(v_relation_proof.alpha, &payload);
  AppendScalar(v_relation_proof.t, &payload);
  AppendScalar(v_relation_proof.u, &payload);

  Envelope out;
  out.session_id = session_id();
  out.from = self_id();
  out.to = kBroadcastPartyId;
  out.type = MessageTypeForPhase5Stage(SignPhase5Stage::kPhase5B);
  out.payload = std::move(payload);

  MaybeAdvanceAfterPhase5B();
  return out;
}

Envelope SignSession::BuildPhase5CCommitEnvelope() {
  if (IsTerminal()) {
    TECDSA_THROW_LOGIC("cannot build phase5C envelope for terminal sign session");
  }
  if (phase_ != SignPhase::kPhase5 || phase5_stage_ != SignPhase5Stage::kPhase5C) {
    TECDSA_THROW_LOGIC("BuildPhase5CCommitEnvelope must be called in sign phase5C");
  }

  local_U_i_ = V_.Mul(local_rho_i_);
  local_T_i_ = A_.Mul(local_l_i_);

  const Bytes commit_message = SerializePointPair(local_U_i_, local_T_i_);
  const CommitmentResult commitment = CommitMessage(kPhase5CCommitDomain, commit_message);
  local_phase5c_randomness_ = commitment.randomness;
  local_phase5c_commitment_ = commitment.commitment;

  local_phase5c_ready_ = true;
  phase5c_commitments_[self_id()] = local_phase5c_commitment_;

  Envelope out;
  out.session_id = session_id();
  out.from = self_id();
  out.to = kBroadcastPartyId;
  out.type = MessageTypeForPhase5Stage(SignPhase5Stage::kPhase5C);
  out.payload = local_phase5c_commitment_;

  MaybeAdvanceAfterPhase5C();
  return out;
}

Envelope SignSession::BuildPhase5DOpenEnvelope() {
  if (IsTerminal()) {
    TECDSA_THROW_LOGIC("cannot build phase5D envelope for terminal sign session");
  }
  if (phase_ != SignPhase::kPhase5 || phase5_stage_ != SignPhase5Stage::kPhase5D) {
    TECDSA_THROW_LOGIC("BuildPhase5DOpenEnvelope must be called in sign phase5D");
  }

  local_phase5d_ready_ = true;
  phase5d_open_data_[self_id()] =
      Phase5DOpenData{.U_i = local_U_i_, .T_i = local_T_i_, .randomness = local_phase5c_randomness_};

  Bytes payload;
  payload.reserve(kPointCompressedLen * 2 + 4 + local_phase5c_randomness_.size());
  AppendPoint(local_U_i_, &payload);
  AppendPoint(local_T_i_, &payload);
  AppendSizedField(local_phase5c_randomness_, &payload);

  Envelope out;
  out.session_id = session_id();
  out.from = self_id();
  out.to = kBroadcastPartyId;
  out.type = MessageTypeForPhase5Stage(SignPhase5Stage::kPhase5D);
  out.payload = std::move(payload);

  MaybeAdvanceAfterPhase5D();
  return out;
}

Envelope SignSession::BuildPhase5ERevealEnvelope() {
  if (IsTerminal()) {
    TECDSA_THROW_LOGIC("cannot build phase5E envelope for terminal sign session");
  }
  if (phase_ != SignPhase::kPhase5 || phase5_stage_ != SignPhase5Stage::kPhase5E) {
    TECDSA_THROW_LOGIC("BuildPhase5ERevealEnvelope must be called in sign phase5E");
  }

  local_phase5e_ready_ = true;
  phase5e_revealed_s_[self_id()] = local_s_i_;

  Envelope out;
  out.session_id = session_id();
  out.from = self_id();
  out.to = kBroadcastPartyId;
  out.type = MessageTypeForPhase5Stage(SignPhase5Stage::kPhase5E);
  AppendScalar(local_s_i_, &out.payload);

  MaybeAdvanceAfterPhase5E();
  return out;
}

bool SignSession::HandleEnvelope(const Envelope& envelope) {
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
    case SignPhase::kPhase1:
      if (envelope.type != MessageTypeForPhase(SignPhase::kPhase1)) {
        Abort("unexpected envelope type for sign phase1");
        return false;
      }
      return HandlePhase1CommitEnvelope(envelope);
    case SignPhase::kPhase2:
      if (envelope.type == MessageTypeForPhase(SignPhase::kPhase2)) {
        return HandlePhase2InitEnvelope(envelope);
      }
      if (envelope.type == Phase2ResponseMessageType()) {
        return HandlePhase2ResponseEnvelope(envelope);
      }
      Abort("unexpected envelope type for sign phase2");
      return false;
    case SignPhase::kPhase3:
      if (envelope.type != MessageTypeForPhase(SignPhase::kPhase3)) {
        Abort("unexpected envelope type for sign phase3");
        return false;
      }
      return HandlePhase3DeltaEnvelope(envelope);
    case SignPhase::kPhase4:
      if (envelope.type != MessageTypeForPhase(SignPhase::kPhase4)) {
        Abort("unexpected envelope type for sign phase4");
        return false;
      }
      return HandlePhase4OpenEnvelope(envelope);
    case SignPhase::kPhase5:
      switch (phase5_stage_) {
        case SignPhase5Stage::kPhase5A:
          if (envelope.type != MessageTypeForPhase5Stage(SignPhase5Stage::kPhase5A)) {
            Abort("unexpected envelope type for sign phase5A");
            return false;
          }
          return HandlePhase5ACommitEnvelope(envelope);
        case SignPhase5Stage::kPhase5B:
          if (envelope.type != MessageTypeForPhase5Stage(SignPhase5Stage::kPhase5B)) {
            Abort("unexpected envelope type for sign phase5B");
            return false;
          }
          return HandlePhase5BOpenEnvelope(envelope);
        case SignPhase5Stage::kPhase5C:
          if (envelope.type != MessageTypeForPhase5Stage(SignPhase5Stage::kPhase5C)) {
            Abort("unexpected envelope type for sign phase5C");
            return false;
          }
          return HandlePhase5CCommitEnvelope(envelope);
        case SignPhase5Stage::kPhase5D:
          if (envelope.type != MessageTypeForPhase5Stage(SignPhase5Stage::kPhase5D)) {
            Abort("unexpected envelope type for sign phase5D");
            return false;
          }
          return HandlePhase5DOpenEnvelope(envelope);
        case SignPhase5Stage::kPhase5E:
          if (envelope.type != MessageTypeForPhase5Stage(SignPhase5Stage::kPhase5E)) {
            Abort("unexpected envelope type for sign phase5E");
            return false;
          }
          return HandlePhase5ERevealEnvelope(envelope);
        case SignPhase5Stage::kCompleted:
          return false;
      }
      TECDSA_THROW_ARGUMENT("invalid sign phase5 stage");
    case SignPhase::kCompleted:
      return false;
  }
  TECDSA_THROW_ARGUMENT("invalid sign phase");
}

Envelope SignSession::MakePhaseBroadcastEnvelope(const Bytes& payload) const {
  if (IsTerminal()) {
    TECDSA_THROW_LOGIC("cannot create envelope for terminal session");
  }

  Envelope out;
  out.session_id = session_id();
  out.from = self_id();
  out.to = kBroadcastPartyId;
  out.type =
      (phase_ == SignPhase::kPhase5) ? MessageTypeForPhase5Stage(phase5_stage_) : MessageTypeForPhase(phase_);
  out.payload = payload;
  return out;
}

bool SignSession::HasResult() const {
  return status() == SessionStatus::kCompleted && phase_ == SignPhase::kCompleted && has_result_;
}

const SignResult& SignSession::result() const {
  if (!HasResult()) {
    TECDSA_THROW_LOGIC("sign result is not ready");
  }
  return result_;
}

bool SignSession::PollTimeout(std::chrono::steady_clock::time_point now) {
  const bool timed_out = Session::PollTimeout(now);
  if (timed_out) {
    ClearSensitiveIntermediates();
  }
  return timed_out;
}

uint32_t SignSession::MessageTypeForPhase(SignPhase phase) {
  switch (phase) {
    case SignPhase::kPhase1:
      return static_cast<uint32_t>(SignMessageType::kPhase1);
    case SignPhase::kPhase2:
      return static_cast<uint32_t>(SignMessageType::kPhase2);
    case SignPhase::kPhase3:
      return static_cast<uint32_t>(SignMessageType::kPhase3);
    case SignPhase::kPhase4:
      return static_cast<uint32_t>(SignMessageType::kPhase4);
    case SignPhase::kPhase5:
      return static_cast<uint32_t>(SignMessageType::kPhase5A);
    case SignPhase::kCompleted:
      return static_cast<uint32_t>(SignMessageType::kAbort);
  }
  TECDSA_THROW_ARGUMENT("invalid sign phase");
}

uint32_t SignSession::Phase2ResponseMessageType() {
  return static_cast<uint32_t>(SignMessageType::kPhase2Response);
}

void SignSession::ClearSensitiveIntermediates() {
  SecureZeroize(&local_x_i_);
  SecureZeroize(&local_w_i_);
  SecureZeroize(&local_k_i_);
  SecureZeroize(&local_gamma_i_);
  SecureZeroize(&local_delta_i_);
  SecureZeroize(&local_sigma_i_);
  SecureZeroize(&delta_);
  SecureZeroize(&delta_inv_);
  SecureZeroize(&local_s_i_);
  SecureZeroize(&local_l_i_);
  SecureZeroize(&local_rho_i_);
  SecureZeroize(&s_);
  SecureZeroize(&phase2_mta_initiator_sum_);
  SecureZeroize(&phase2_mta_responder_sum_);
  SecureZeroize(&phase2_mtawc_initiator_sum_);
  SecureZeroize(&phase2_mtawc_responder_sum_);

  SecureZeroize(&fixed_k_i_);
  SecureZeroize(&fixed_gamma_i_);
  SecureZeroize(&local_phase1_randomness_);
  SecureZeroize(&local_phase1_commitment_);
  SecureZeroize(&local_phase5a_randomness_);
  SecureZeroize(&local_phase5a_commitment_);
  SecureZeroize(&local_phase5c_randomness_);
  SecureZeroize(&local_phase5c_commitment_);

  SecureZeroize(&lagrange_coefficients_);
  SecureZeroize(&w_shares_);
  SecureZeroize(&phase3_delta_shares_);
  SecureZeroize(&phase5e_revealed_s_);
  SecureZeroize(&phase1_commitments_);
  SecureZeroize(&phase5a_commitments_);
  SecureZeroize(&phase5c_commitments_);

  for (auto& [instance_key, instance] : phase2_initiator_instances_) {
    (void)instance_key;
    instance.c1 = BigInt(0);
    instance.c1_randomness = BigInt(0);
    SecureZeroize(&instance.instance_id);
  }
  phase2_initiator_instances_.clear();
  phase2_responder_requests_seen_.clear();

  for (Envelope& envelope : phase2_outbox_) {
    SecureZeroize(&envelope.payload);
  }
  phase2_outbox_.clear();

  for (auto& [party, open_data] : phase4_open_data_) {
    (void)party;
    SecureZeroize(&open_data.gamma_proof.z);
    SecureZeroize(&open_data.randomness);
  }
  phase4_open_data_.clear();

  for (auto& [party, open_data] : phase5b_open_data_) {
    (void)party;
    SecureZeroize(&open_data.a_schnorr_proof.z);
    SecureZeroize(&open_data.v_relation_proof.t);
    SecureZeroize(&open_data.v_relation_proof.u);
    SecureZeroize(&open_data.randomness);
  }
  phase5b_open_data_.clear();

  for (auto& [party, open_data] : phase5d_open_data_) {
    (void)party;
    SecureZeroize(&open_data.randomness);
  }
  phase5d_open_data_.clear();
}

void SignSession::Abort(const std::string& reason) {
  if (IsTerminal()) {
    return;
  }
  ClearSensitiveIntermediates();
  Session::Abort(reason);
}

void SignSession::Complete() {
  if (IsTerminal()) {
    return;
  }
  ClearSensitiveIntermediates();
  Session::Complete();
}

uint32_t SignSession::MessageTypeForPhase5Stage(SignPhase5Stage stage) {
  switch (stage) {
    case SignPhase5Stage::kPhase5A:
      return static_cast<uint32_t>(SignMessageType::kPhase5A);
    case SignPhase5Stage::kPhase5B:
      return static_cast<uint32_t>(SignMessageType::kPhase5B);
    case SignPhase5Stage::kPhase5C:
      return static_cast<uint32_t>(SignMessageType::kPhase5C);
    case SignPhase5Stage::kPhase5D:
      return static_cast<uint32_t>(SignMessageType::kPhase5D);
    case SignPhase5Stage::kPhase5E:
      return static_cast<uint32_t>(SignMessageType::kPhase5E);
    case SignPhase5Stage::kCompleted:
      return static_cast<uint32_t>(SignMessageType::kAbort);
  }
  TECDSA_THROW_ARGUMENT("invalid sign phase5 stage");
}


}  // namespace tecdsa
