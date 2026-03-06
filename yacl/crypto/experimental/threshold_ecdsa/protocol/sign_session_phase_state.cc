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
#include <future>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/commitment.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/ecdsa_verify.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/random.h"
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/sign_session.h"
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/sign_session_internal.h"

namespace tecdsa {
using namespace sign_internal;

void SignSession::PrepareResharedSigningShares() {
  lagrange_coefficients_ = ComputeLagrangeAtZero(participants_);

  const auto lambda_self_it = lagrange_coefficients_.find(self_id());
  if (lambda_self_it == lagrange_coefficients_.end()) {
    TECDSA_THROW_ARGUMENT("missing lagrange coefficient for self");
  }

  local_w_i_ = lambda_self_it->second * local_x_i_;
  w_shares_[self_id()] = local_w_i_;

  std::vector<ECPoint> w_points;
  w_points.reserve(participants_.size());
  for (PartyIndex party : participants_) {
    const auto lambda_it = lagrange_coefficients_.find(party);
    const auto x_pub_it = all_X_i_.find(party);
    if (lambda_it == lagrange_coefficients_.end() ||
        x_pub_it == all_X_i_.end()) {
      TECDSA_THROW_ARGUMENT(
          "missing lagrange coefficient or X_i for participant");
    }

    try {
      W_points_[party] = x_pub_it->second.Mul(lambda_it->second);
    } catch (const std::exception& ex) {
      TECDSA_THROW_ARGUMENT(std::string("failed to compute W_i: ") + ex.what());
    }
    w_points.push_back(W_points_.at(party));
  }

  try {
    const ECPoint reconstructed_y = SumPointsOrThrow(w_points);
    if (reconstructed_y != public_key_y_) {
      TECDSA_THROW_ARGUMENT("W_i aggregation does not reconstruct y");
    }
  } catch (const std::exception& ex) {
    TECDSA_THROW_ARGUMENT(std::string("failed to validate W_i aggregation: ") +
                          ex.what());
  }
}

void SignSession::PreparePhase1SecretsIfNeeded() {
  if (!local_phase1_commitment_.empty()) {
    return;
  }

  local_k_i_ = fixed_k_i_.value_or(RandomNonZeroScalar());
  local_gamma_i_ = fixed_gamma_i_.value_or(RandomNonZeroScalar());
  if (local_k_i_.value() == 0 || local_gamma_i_.value() == 0) {
    TECDSA_THROW_ARGUMENT("fixed k_i and gamma_i must be non-zero");
  }

  local_Gamma_i_ = ECPoint::GeneratorMultiply(local_gamma_i_);
  const Bytes gamma_bytes = local_Gamma_i_.ToCompressedBytes();
  const CommitmentResult commitment =
      CommitMessage(kPhase1CommitDomain, gamma_bytes);
  local_phase1_randomness_ = commitment.randomness;
  local_phase1_commitment_ = commitment.commitment;
}

void SignSession::InitializePhase2InstancesIfNeeded() {
  if (phase2_instances_initialized_) {
    return;
  }
  if (phase_ != SignPhase::kPhase2) {
    TECDSA_THROW_LOGIC(
        "phase2 instances can only be initialized in sign phase2");
  }

  PreparePhase1SecretsIfNeeded();

  const auto self_pk_it = all_paillier_public_.find(self_id());
  if (self_pk_it == all_paillier_public_.end()) {
    TECDSA_THROW_LOGIC(
        "missing local Paillier or peer auxiliary parameters for phase2 init");
  }
  const BigInt local_n = self_pk_it->second.n;
  const BigInt local_k_value = local_k_i_.mp_value();
  const Bytes session_id_bytes = session_id();
  const PartyIndex initiator_id = self_id();

  struct PendingInit {
    PartyIndex peer = 0;
    MtaType type = MtaType::kTimesGamma;
    Bytes instance_id;
    BigInt c1;
    BigInt c1_randomness;
    AuxRsaParams peer_aux;
  };

  std::vector<PendingInit> pending;
  pending.reserve(peers_.size() * 2);
  std::unordered_set<std::string> reserved_instance_keys;
  reserved_instance_keys.reserve(peers_.size() * 2);

  for (PartyIndex peer : participants_) {
    if (peer == self_id()) {
      continue;
    }

    const auto peer_aux_it = all_aux_rsa_params_.find(peer);
    if (peer_aux_it == all_aux_rsa_params_.end()) {
      TECDSA_THROW_LOGIC(
          "missing local Paillier or peer auxiliary parameters for phase2 "
          "init");
    }

    for (MtaType type : {MtaType::kTimesGamma, MtaType::kTimesW}) {
      Bytes instance_id = RandomMtaInstanceId();
      std::string instance_key = BytesToKey(instance_id);
      while (phase2_initiator_instances_.contains(instance_key) ||
             reserved_instance_keys.contains(instance_key)) {
        instance_id = RandomMtaInstanceId();
        instance_key = BytesToKey(instance_id);
      }
      reserved_instance_keys.insert(instance_key);

      const PaillierCiphertextWithRandomBigInt encrypted =
          local_paillier_->EncryptWithRandomBigInt(local_k_value);
      pending.push_back(PendingInit{
          .peer = peer,
          .type = type,
          .instance_id = instance_id,
          .c1 = encrypted.ciphertext,
          .c1_randomness = encrypted.randomness,
          .peer_aux = peer_aux_it->second,
      });
    }
  }

  ThreadPool& pool = Phase2ThreadPool();
  std::vector<std::future<Bytes>> payload_futures;
  payload_futures.reserve(pending.size());
  for (const PendingInit& init : pending) {
    payload_futures.push_back(pool.Submit(
        [init, local_n, local_k_value, session_id_bytes, initiator_id]() {
          const MtaProofContext proof_ctx{
              .session_id = session_id_bytes,
              .initiator_id = initiator_id,
              .responder_id = init.peer,
              .mta_instance_id = init.instance_id,
          };
          const A1RangeProof a1_proof =
              ProveA1Range(proof_ctx, local_n, init.peer_aux, init.c1,
                           local_k_value, init.c1_randomness);

          Bytes payload;
          AppendU32Be(static_cast<uint32_t>(init.type), &payload);
          AppendSizedField(init.instance_id, &payload);
          AppendMpIntField(init.c1, &payload);
          AppendA1RangeProof(a1_proof, &payload);
          return payload;
        }));
  }

  std::vector<Bytes> payloads;
  payloads.reserve(payload_futures.size());
  for (std::future<Bytes>& future : payload_futures) {
    payloads.push_back(future.get());
  }

  for (size_t i = 0; i < pending.size(); ++i) {
    const PendingInit& init = pending[i];
    const std::string instance_key = BytesToKey(init.instance_id);
    phase2_initiator_instances_.emplace(instance_key,
                                        Phase2InitiatorInstance{
                                            .responder = init.peer,
                                            .type = init.type,
                                            .instance_id = init.instance_id,
                                            .c1 = init.c1,
                                            .c1_randomness = init.c1_randomness,
                                            .response_received = false,
                                        });

    Envelope out;
    out.session_id = session_id();
    out.from = self_id();
    out.to = init.peer;
    out.type = MessageTypeForPhase(SignPhase::kPhase2);
    out.payload = std::move(payloads[i]);
    phase2_outbox_.push_back(std::move(out));
  }

  phase2_instances_initialized_ = true;
}

void SignSession::MaybeFinalizePhase2AndAdvance() {
  if (phase_ != SignPhase::kPhase2 || local_phase2_ready_) {
    return;
  }
  if (!phase2_instances_initialized_) {
    return;
  }
  if (!phase2_outbox_.empty()) {
    return;
  }

  const size_t expected_instance_count = peers_.size() * 2;
  if (phase2_initiator_instances_.size() != expected_instance_count) {
    return;
  }
  if (phase2_responder_requests_seen_.size() != expected_instance_count) {
    return;
  }

  for (const auto& [instance_key, instance] : phase2_initiator_instances_) {
    (void)instance_key;
    if (!instance.response_received) {
      return;
    }
  }

  local_delta_i_ = (local_k_i_ * local_gamma_i_) + phase2_mta_initiator_sum_ +
                   phase2_mta_responder_sum_;
  local_sigma_i_ = (local_k_i_ * local_w_i_) + phase2_mtawc_initiator_sum_ +
                   phase2_mtawc_responder_sum_;

  local_phase2_ready_ = true;
}

void SignSession::ComputeDeltaInverseAndAdvanceToPhase4() {
  Scalar delta;
  for (PartyIndex party : participants_) {
    const auto delta_it = phase3_delta_shares_.find(party);
    if (delta_it == phase3_delta_shares_.end()) {
      Abort("missing phase3 delta share");
      return;
    }
    delta = delta + delta_it->second;
  }

  if (delta.value() == 0) {
    Abort("aggregated delta is zero");
    return;
  }

  const std::optional<Scalar> delta_inv = InvertScalar(delta);
  if (!delta_inv.has_value()) {
    Abort("failed to invert aggregated delta");
    return;
  }

  delta_ = delta;
  delta_inv_ = *delta_inv;
  phase_ = SignPhase::kPhase4;
}

void SignSession::ComputeRAndAdvanceToPhase5() {
  std::vector<ECPoint> gammas;
  gammas.reserve(participants_.size());
  for (PartyIndex party : participants_) {
    const auto gamma_it = phase4_open_data_.find(party);
    if (gamma_it == phase4_open_data_.end()) {
      Abort("missing phase4 opened gamma point");
      return;
    }
    gammas.push_back(gamma_it->second.gamma_i);
  }

  try {
    Gamma_ = SumPointsOrThrow(gammas);
    R_ = Gamma_.Mul(delta_inv_);
  } catch (const std::exception& ex) {
    Abort(std::string("failed to compute R in phase4: ") + ex.what());
    return;
  }

  r_ = XCoordinateModQ(R_);
  if (r_.value() == 0) {
    Abort("computed r is zero");
    return;
  }

  phase_ = SignPhase::kPhase5;
  phase5_stage_ = SignPhase5Stage::kPhase5A;
}

void SignSession::ComputePhase5VAAndAdvanceToStage5C() {
  std::vector<ECPoint> v_points;
  std::vector<ECPoint> a_points;
  v_points.reserve(participants_.size());
  a_points.reserve(participants_.size());

  for (PartyIndex party : participants_) {
    const auto open_it = phase5b_open_data_.find(party);
    if (open_it == phase5b_open_data_.end()) {
      Abort("missing phase5B open data");
      return;
    }
    v_points.push_back(open_it->second.V_i);
    a_points.push_back(open_it->second.A_i);
  }

  try {
    V_ = SumPointsOrThrow(v_points);
    A_ = SumPointsOrThrow(a_points);

    if (message_scalar_.value() != 0) {
      const Scalar neg_m = Scalar() - message_scalar_;
      V_ = V_.Add(ECPoint::GeneratorMultiply(neg_m));
    }

    const Scalar neg_r = Scalar() - r_;
    V_ = V_.Add(public_key_y_.Mul(neg_r));
  } catch (const std::exception& ex) {
    Abort(std::string("failed to compute phase5 V/A aggregates: ") + ex.what());
    return;
  }

  phase5_stage_ = SignPhase5Stage::kPhase5C;
}

void SignSession::VerifyPhase5DAndAdvanceToStage5E() {
  std::vector<ECPoint> u_points;
  std::vector<ECPoint> t_points;
  u_points.reserve(participants_.size());
  t_points.reserve(participants_.size());

  for (PartyIndex party : participants_) {
    const auto open_it = phase5d_open_data_.find(party);
    if (open_it == phase5d_open_data_.end()) {
      Abort("missing phase5D open data");
      return;
    }
    u_points.push_back(open_it->second.U_i);
    t_points.push_back(open_it->second.T_i);
  }

  try {
    const ECPoint sum_u = SumPointsOrThrow(u_points);
    const ECPoint sum_t = SumPointsOrThrow(t_points);
    if (sum_u != sum_t) {
      Abort("phase5D consistency check failed");
      return;
    }
  } catch (const std::exception& ex) {
    Abort(std::string("failed to validate phase5D consistency: ") + ex.what());
    return;
  }

  phase5_stage_ = SignPhase5Stage::kPhase5E;
}

void SignSession::FinalizeSignatureAndComplete() {
  Scalar s;
  for (PartyIndex party : participants_) {
    const auto s_it = phase5e_revealed_s_.find(party);
    if (s_it == phase5e_revealed_s_.end()) {
      Abort("missing phase5E revealed share");
      return;
    }
    s = s + s_it->second;
  }

  if (s.value() == 0) {
    Abort("aggregated signature scalar s is zero");
    return;
  }

  Scalar canonical_s = s;
  if (IsHighScalar(canonical_s)) {
    canonical_s = Scalar() - canonical_s;
  }

  if (!VerifyEcdsaSignatureMath(public_key_y_, msg32_, r_, canonical_s)) {
    Abort("final ECDSA signature verification failed");
    return;
  }

  s_ = canonical_s;
  result_.r = r_;
  result_.s = s_;
  result_.R = R_;
  result_.local_w_i = local_w_i_;
  result_.lagrange_coefficients = lagrange_coefficients_;
  result_.w_shares = w_shares_;
  result_.W_points = W_points_;
  has_result_ = true;

  phase5_stage_ = SignPhase5Stage::kCompleted;
  phase_ = SignPhase::kCompleted;
  Complete();
}

void SignSession::MaybeAdvanceAfterPhase1() {
  if (phase_ != SignPhase::kPhase1) {
    return;
  }
  if (!local_phase1_ready_) {
    return;
  }
  if (seen_phase1_.size() != peers_.size()) {
    return;
  }
  if (phase1_commitments_.size() != participants_.size()) {
    return;
  }
  phase_ = SignPhase::kPhase2;
}

void SignSession::MaybeAdvanceAfterPhase2() {
  if (phase_ != SignPhase::kPhase2) {
    return;
  }
  MaybeFinalizePhase2AndAdvance();
  if (!local_phase2_ready_) {
    return;
  }
  phase_ = SignPhase::kPhase3;
}

void SignSession::MaybeAdvanceAfterPhase3() {
  if (phase_ != SignPhase::kPhase3) {
    return;
  }
  if (!local_phase3_ready_) {
    return;
  }
  if (seen_phase3_.size() != peers_.size()) {
    return;
  }
  if (phase3_delta_shares_.size() != participants_.size()) {
    return;
  }
  ComputeDeltaInverseAndAdvanceToPhase4();
}

void SignSession::MaybeAdvanceAfterPhase4() {
  if (phase_ != SignPhase::kPhase4) {
    return;
  }
  if (!local_phase4_ready_) {
    return;
  }
  if (seen_phase4_.size() != peers_.size()) {
    return;
  }
  if (phase4_open_data_.size() != participants_.size()) {
    return;
  }
  ComputeRAndAdvanceToPhase5();
}

void SignSession::MaybeAdvanceAfterPhase5A() {
  if (phase_ != SignPhase::kPhase5 ||
      phase5_stage_ != SignPhase5Stage::kPhase5A) {
    return;
  }
  if (!local_phase5a_ready_) {
    return;
  }
  if (seen_phase5a_.size() != peers_.size()) {
    return;
  }
  if (phase5a_commitments_.size() != participants_.size()) {
    return;
  }
  phase5_stage_ = SignPhase5Stage::kPhase5B;
}

void SignSession::MaybeAdvanceAfterPhase5B() {
  if (phase_ != SignPhase::kPhase5 ||
      phase5_stage_ != SignPhase5Stage::kPhase5B) {
    return;
  }
  if (!local_phase5b_ready_) {
    return;
  }
  if (seen_phase5b_.size() != peers_.size()) {
    return;
  }
  if (phase5b_open_data_.size() != participants_.size()) {
    return;
  }
  ComputePhase5VAAndAdvanceToStage5C();
}

void SignSession::MaybeAdvanceAfterPhase5C() {
  if (phase_ != SignPhase::kPhase5 ||
      phase5_stage_ != SignPhase5Stage::kPhase5C) {
    return;
  }
  if (!local_phase5c_ready_) {
    return;
  }
  if (seen_phase5c_.size() != peers_.size()) {
    return;
  }
  if (phase5c_commitments_.size() != participants_.size()) {
    return;
  }
  phase5_stage_ = SignPhase5Stage::kPhase5D;
}

void SignSession::MaybeAdvanceAfterPhase5D() {
  if (phase_ != SignPhase::kPhase5 ||
      phase5_stage_ != SignPhase5Stage::kPhase5D) {
    return;
  }
  if (!local_phase5d_ready_) {
    return;
  }
  if (seen_phase5d_.size() != peers_.size()) {
    return;
  }
  if (phase5d_open_data_.size() != participants_.size()) {
    return;
  }
  VerifyPhase5DAndAdvanceToStage5E();
}

void SignSession::MaybeAdvanceAfterPhase5E() {
  if (phase_ != SignPhase::kPhase5 ||
      phase5_stage_ != SignPhase5Stage::kPhase5E) {
    return;
  }
  if (!local_phase5e_ready_) {
    return;
  }
  if (seen_phase5e_.size() != peers_.size()) {
    return;
  }
  if (phase5e_revealed_s_.size() != participants_.size()) {
    return;
  }
  FinalizeSignatureAndComplete();
}

SignSession::SchnorrProof SignSession::BuildSchnorrProof(
    const ECPoint& statement, const Scalar& witness) const {
  if (witness.value() == 0) {
    TECDSA_THROW_ARGUMENT("schnorr witness must be non-zero");
  }

  while (true) {
    const Scalar r = RandomNonZeroScalar();
    const ECPoint a = ECPoint::GeneratorMultiply(r);
    const Scalar e =
        BuildSchnorrChallenge(session_id(), self_id(), statement, a);
    const Scalar z = r + (e * witness);
    if (z.value() == 0) {
      continue;
    }
    return SchnorrProof{.a = a, .z = z};
  }
}

bool SignSession::VerifySchnorrProof(PartyIndex prover_id,
                                     const ECPoint& statement,
                                     const SchnorrProof& proof) const {
  if (proof.z.value() == 0) {
    return false;
  }

  try {
    const Scalar e =
        BuildSchnorrChallenge(session_id(), prover_id, statement, proof.a);
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

SignSession::VRelationProof SignSession::BuildVRelationProof(
    const ECPoint& r_statement, const ECPoint& v_statement,
    const Scalar& s_witness, const Scalar& l_witness) const {
  while (true) {
    const Scalar a = Csprng::RandomScalar();
    const Scalar b = Csprng::RandomScalar();
    if (a.value() == 0 && b.value() == 0) {
      continue;
    }

    ECPoint alpha;
    try {
      alpha = BuildRGeneratorLinearCombination(r_statement, a, b);
    } catch (const std::exception&) {
      continue;
    }

    const Scalar c = BuildVRelationChallenge(session_id(), self_id(),
                                             r_statement, v_statement, alpha);
    const Scalar t = a + (c * s_witness);
    const Scalar u = b + (c * l_witness);
    if (t.value() == 0 && u.value() == 0) {
      continue;
    }

    return VRelationProof{
        .alpha = alpha,
        .t = t,
        .u = u,
    };
  }
}

bool SignSession::VerifyVRelationProof(PartyIndex prover_id,
                                       const ECPoint& r_statement,
                                       const ECPoint& v_statement,
                                       const VRelationProof& proof) const {
  if (proof.t.value() == 0 && proof.u.value() == 0) {
    return false;
  }

  try {
    const Scalar c = BuildVRelationChallenge(
        session_id(), prover_id, r_statement, v_statement, proof.alpha);
    const ECPoint lhs =
        BuildRGeneratorLinearCombination(r_statement, proof.t, proof.u);

    ECPoint rhs = proof.alpha;
    if (c.value() != 0) {
      rhs = rhs.Add(v_statement.Mul(c));
    }
    return lhs == rhs;
  } catch (const std::exception&) {
    return false;
  }
}

}  // namespace tecdsa
