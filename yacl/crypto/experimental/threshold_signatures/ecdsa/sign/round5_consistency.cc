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

#include "yacl/crypto/experimental/threshold_signatures/ecdsa/sign/sign.h"

#include <exception>
#include <string>
#include <vector>

#include "yacl/crypto/experimental/threshold_signatures/common/errors.h"
#include "yacl/crypto/experimental/threshold_signatures/core/commitment/commitment.h"
#include "yacl/crypto/experimental/threshold_signatures/core/proof/schnorr.h"
#include "yacl/crypto/experimental/threshold_signatures/core/protocol/message_store.h"
#include "yacl/crypto/experimental/threshold_signatures/core/vss/dealerless_dkg.h"
#include "yacl/crypto/experimental/threshold_signatures/core/vss/feldman.h"
#include "yacl/crypto/experimental/threshold_signatures/ecdsa/sign/internal.h"
#include "yacl/crypto/experimental/threshold_signatures/ecdsa/sign/relation_proofs.h"
#include "yacl/crypto/experimental/threshold_signatures/ecdsa/verify/verify.h"

namespace tecdsa::ecdsa::sign {
namespace {

namespace relation = tecdsa::ecdsa::sign;
namespace verify = tecdsa::ecdsa::verify;

}  // namespace

SignRound5AMsg SignParty::MakeRound5A(
    const PeerMap<SignRound4Msg>& peer_round4) {
  if (state_.rounds.HasReached(SignStep::kRound5ADone)) {
    TECDSA_THROW_LOGIC("MakeRound5A must not be called twice");
  }
  state_.rounds.RequireReached(SignStep::kRound4Done,
                               "MakeRound4 must be completed before MakeRound5A");

  core::protocol::RequireExactlyPeerMessages(peer_round4, peers_,
                                             "peer_round4");
  std::vector<ECPoint> gamma_points;
  gamma_points.reserve(cfg_.participants.size());
  gamma_points.push_back(state_.round1.Gamma_i);

  for (PartyIndex peer : peers_) {
    const SignRound4Msg& msg = peer_round4.at(peer);
    const auto commitment_it = state_.round1.commitments.find(peer);
    if (commitment_it == state_.round1.commitments.end()) {
      TECDSA_THROW_LOGIC("missing stored round1 commitment for peer");
    }
    if (!core::commitment::VerifyCommitment(
            core::DefaultEcdsaSuite(), internal::kPhase1CommitDomain,
            msg.gamma_i.ToCompressedBytes(), msg.randomness,
            commitment_it->second)) {
      TECDSA_THROW_ARGUMENT(
          "round4 gamma opening does not match round1 commitment");
    }
    if (!core::proof::VerifySchnorrProof(core::DefaultEcdsaSuite(),
                                         cfg_.session_id, peer, msg.gamma_i,
                                         msg.gamma_proof)) {
      TECDSA_THROW_ARGUMENT("round4 gamma Schnorr proof verification failed");
    }
    gamma_points.push_back(msg.gamma_i);
  }

  try {
    state_.delta.gamma = core::vss::SumPointsOrThrow(gamma_points);
    state_.delta.R = state_.delta.gamma.Mul(state_.delta.delta_inv);
  } catch (const std::exception& ex) {
    TECDSA_THROW_ARGUMENT(std::string("failed to compute R in round5A: ") +
                          ex.what());
  }
  state_.delta.r = verify::XCoordinateModQ(state_.delta.R);
  if (state_.delta.r.value() == 0) {
    TECDSA_THROW_ARGUMENT("computed r is zero");
  }

  EnsureRound5ASharePrepared();
  return SignRound5AMsg{
      .commitment =
          state_.final_share.round5a_commitments.at(cfg_.self_id)};
}

SignRound5BMsg SignParty::MakeRound5B(
    const PeerMap<SignRound5AMsg>& peer_round5a) {
  if (state_.rounds.HasReached(SignStep::kRound5BDone)) {
    TECDSA_THROW_LOGIC("MakeRound5B must not be called twice");
  }
  state_.rounds.RequireReached(SignStep::kRound5ADone,
                               "MakeRound5A must be completed before MakeRound5B");

  core::protocol::RequireExactlyPeerMessages(peer_round5a, peers_,
                                             "peer_round5a");
  internal::StoreCommitments(peer_round5a, peers_,
                             &state_.final_share.round5a_commitments,
                             "sign round5A commitment");

  state_.rounds.Advance(SignStep::kRound5ADone, SignStep::kRound5BDone,
                        "MakeRound5B must not be called twice");
  return SignRound5BMsg{
      .V_i = state_.final_share.V_i,
      .A_i = state_.final_share.A_i,
      .randomness = state_.final_share.round5a_randomness,
      .a_schnorr_proof = core::proof::BuildSchnorrProof(
          core::DefaultEcdsaSuite(), cfg_.session_id, cfg_.self_id,
          state_.final_share.A_i, state_.final_share.rho_i),
      .v_relation_proof = relation::BuildVRelationProof(
          cfg_.session_id, cfg_.self_id, state_.delta.R,
          state_.final_share.V_i, state_.final_share.s_i,
          state_.final_share.l_i),
  };
}

SignRound5CMsg SignParty::MakeRound5C(
    const PeerMap<SignRound5BMsg>& peer_round5b) {
  if (state_.rounds.HasReached(SignStep::kRound5CDone)) {
    TECDSA_THROW_LOGIC("MakeRound5C must not be called twice");
  }
  state_.rounds.RequireReached(SignStep::kRound5BDone,
                               "MakeRound5B must be completed before MakeRound5C");

  core::protocol::RequireExactlyPeerMessages(peer_round5b, peers_,
                                             "peer_round5b");
  std::vector<ECPoint> v_points;
  std::vector<ECPoint> a_points;
  v_points.reserve(cfg_.participants.size());
  a_points.reserve(cfg_.participants.size());
  v_points.push_back(state_.final_share.V_i);
  a_points.push_back(state_.final_share.A_i);

  for (PartyIndex peer : peers_) {
    const SignRound5BMsg& msg = peer_round5b.at(peer);
    const auto commitment_it =
        state_.final_share.round5a_commitments.find(peer);
    if (commitment_it == state_.final_share.round5a_commitments.end()) {
      TECDSA_THROW_LOGIC("missing stored round5A commitment for peer");
    }

    if (!core::commitment::VerifyCommitment(
            core::DefaultEcdsaSuite(), internal::kPhase5ACommitDomain,
            relation::SerializePointPair(msg.V_i, msg.A_i), msg.randomness,
            commitment_it->second)) {
      TECDSA_THROW_ARGUMENT(
          "round5B opening does not match round5A commitment");
    }
    if (!core::proof::VerifySchnorrProof(core::DefaultEcdsaSuite(),
                                         cfg_.session_id, peer, msg.A_i,
                                         msg.a_schnorr_proof)) {
      TECDSA_THROW_ARGUMENT("round5B A_i Schnorr proof verification failed");
    }
    if (!relation::VerifyVRelationProof(cfg_.session_id, peer, state_.delta.R,
                                        msg.V_i, msg.v_relation_proof)) {
      TECDSA_THROW_ARGUMENT("round5B V relation proof verification failed");
    }

    v_points.push_back(msg.V_i);
    a_points.push_back(msg.A_i);
  }

  try {
    state_.consistency.V = core::vss::SumPointsOrThrow(v_points);
    state_.consistency.A = core::vss::SumPointsOrThrow(a_points);
    if (message_scalar_.value() != 0) {
      state_.consistency.V = state_.consistency.V.Add(
          ECPoint::GeneratorMultiply(Scalar() - message_scalar_));
    }
    state_.consistency.V = state_.consistency.V.Add(
        verified_keygen_data_.raw().y.Mul(Scalar() - state_.delta.r));
    state_.consistency.U_i =
        state_.consistency.V.Mul(state_.final_share.rho_i);
    state_.consistency.T_i =
        state_.consistency.A.Mul(state_.final_share.l_i);
  } catch (const std::exception& ex) {
    TECDSA_THROW_ARGUMENT(std::string("failed to compute round5C values: ") +
                          ex.what());
  }

  const core::commitment::CommitmentResult commit =
      core::commitment::CommitMessage(
          core::DefaultEcdsaSuite(), internal::kPhase5CCommitDomain,
          relation::SerializePointPair(state_.consistency.U_i,
                                       state_.consistency.T_i));
  state_.consistency.round5c_randomness = commit.randomness;
  state_.consistency.round5c_commitments[cfg_.self_id] = commit.commitment;
  state_.rounds.Advance(SignStep::kRound5BDone, SignStep::kRound5CDone,
                        "MakeRound5C must not be called twice");
  return SignRound5CMsg{
      .commitment = state_.consistency.round5c_commitments.at(cfg_.self_id)};
}

SignRound5DMsg SignParty::MakeRound5D(
    const PeerMap<SignRound5CMsg>& peer_round5c) {
  if (state_.rounds.HasReached(SignStep::kRound5DDone)) {
    TECDSA_THROW_LOGIC("MakeRound5D must not be called twice");
  }
  state_.rounds.RequireReached(SignStep::kRound5CDone,
                               "MakeRound5C must be completed before MakeRound5D");

  core::protocol::RequireExactlyPeerMessages(peer_round5c, peers_,
                                             "peer_round5c");
  internal::StoreCommitments(peer_round5c, peers_,
                             &state_.consistency.round5c_commitments,
                             "sign round5C commitment");

  state_.rounds.Advance(SignStep::kRound5CDone, SignStep::kRound5DDone,
                        "MakeRound5D must not be called twice");
  return SignRound5DMsg{
      .U_i = state_.consistency.U_i,
      .T_i = state_.consistency.T_i,
      .randomness = state_.consistency.round5c_randomness,
  };
}

}  // namespace tecdsa::ecdsa::sign
