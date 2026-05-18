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

#include "yacl/crypto/experimental/threshold_signatures/sm2/presign/offline.h"

#include <exception>
#include <functional>
#include <utility>

#include "yacl/crypto/experimental/threshold_signatures/common/errors.h"
#include "yacl/crypto/experimental/threshold_signatures/core/commitment/commitment.h"
#include "yacl/crypto/experimental/threshold_signatures/core/participant/participant_set.h"
#include "yacl/crypto/experimental/threshold_signatures/sm2/common.h"
#include "yacl/crypto/experimental/threshold_signatures/sm2/detection/evidence.h"
#include "yacl/crypto/experimental/threshold_signatures/sm2/proofs/pi_group.h"

namespace tecdsa::sm2::presign {
namespace {

namespace mta = tecdsa::core::mta;

constexpr char kPhase1CommitDomain[] = "SM2/offline/phase1";

}  // namespace

OfflineParty::OfflineParty(OfflineConfig cfg)
    : cfg_(std::move(cfg)),
      delta_session_({.session_id = cfg_.session_id,
                      .self_id = cfg_.self_id,
                      .suite = core::DefaultSm2Suite(),
                      .group = internal::Sm2Group()}) {
  const auto participant_set = core::participant::BuildParticipantSet(
      cfg_.participants, cfg_.self_id, "sm2::presign::OfflineParty");
  peers_ = participant_set.peers;
  if (cfg_.participants.size() !=
      static_cast<size_t>(cfg_.public_keygen_data.threshold) + 1) {
    TECDSA_THROW_ARGUMENT("offline signer set size must equal threshold + 1");
  }
  if (cfg_.local_key_share.z_i.value() == 0) {
    TECDSA_THROW_ARGUMENT("local z share must be non-zero");
  }
  if (cfg_.local_key_share.paillier == nullptr) {
    TECDSA_THROW_ARGUMENT("local Paillier provider must be present");
  }
  const auto lagrange = internal::ComputeLagrangeAtZero(cfg_.participants);
  const auto lambda_it = lagrange.find(cfg_.self_id);
  if (lambda_it == lagrange.end()) {
    TECDSA_THROW_ARGUMENT("missing Lagrange coefficient for signer");
  }
  for (PartyIndex party : cfg_.participants) {
    if (!cfg_.public_keygen_data.all_Y_i.contains(party)) {
      TECDSA_THROW_ARGUMENT("public SM2 Y_i shares must be present");
    }
  }
  local_w_i_ = lambda_it->second * cfg_.local_key_share.z_i;
  if (local_w_i_.value() == 0) {
    TECDSA_THROW_ARGUMENT("weighted SM2 signing share must be non-zero");
  }
  std::vector<ECPoint> w_points;
  w_points.reserve(cfg_.participants.size());
  for (PartyIndex party : cfg_.participants) {
    const auto party_lambda_it = lagrange.find(party);
    if (party_lambda_it == lagrange.end()) {
      TECDSA_THROW_ARGUMENT("missing Lagrange coefficient for signer subset");
    }
    w_points_[party] =
        cfg_.public_keygen_data.all_Y_i.at(party).Mul(party_lambda_it->second);
    w_points.push_back(w_points_.at(party));
  }
  local_W_i_ = w_points_.at(cfg_.self_id);
  if (ECPoint::GeneratorMultiply(local_w_i_) != local_W_i_) {
    TECDSA_THROW_ARGUMENT("local SM2 W_i does not match weighted signing share");
  }
  W_ = internal::SumPointsOrThrow(w_points);
  local_k_i_ = internal::Sm2Zero();
  delta_initiator_sum_ = internal::Sm2Zero();
  delta_responder_sum_ = internal::Sm2Zero();
  local_delta_i_ = internal::Sm2Zero();
}

void OfflineParty::EnsureRound1Prepared() {
  if (round1_done_) {
    return;
  }

  local_k_i_ = internal::RandomNonZeroSm2Scalar();
  local_K_i_ = ECPoint::GeneratorMultiply(local_k_i_);
  const auto commit = core::commitment::CommitMessage(
      core::DefaultSm2Suite(), kPhase1CommitDomain,
      local_K_i_.ToCompressedBytes());
  local_randomness_ = commit.randomness;
  phase1_commitments_[cfg_.self_id] = commit.commitment;
  round1_done_ = true;
}

Round1Msg OfflineParty::MakeRound1() {
  EnsureRound1Prepared();
  return Round1Msg{.commitment = phase1_commitments_.at(cfg_.self_id)};
}

std::vector<Round2Request> OfflineParty::MakeRound2Requests(
    const PeerMap<Round1Msg>& peer_round1) {
  if (round2_requests_done_) {
    TECDSA_THROW_LOGIC("MakeRound2Requests must not be called twice");
  }

  EnsureRound1Prepared();
  core::participant::RequireExactlyPeers(peer_round1, cfg_.participants,
                                         cfg_.self_id, "peer_round1");
  std::vector<Round2Request> out;
  out.reserve(peers_.size());
  for (PartyIndex peer : peers_) {
    phase1_commitments_[peer] = peer_round1.at(peer).commitment;
    out.push_back(delta_session_.InitiatorInitWithCheck({
        .responder_id = peer,
        .initiator_paillier = cfg_.local_key_share.paillier.get(),
        .responder_aux = &cfg_.public_keygen_data.all_aux_rsa_params.at(peer),
        .initiator_secret = local_k_i_,
    }));
  }
  round2_requests_done_ = true;
  return out;
}

detection::DetectionResult<std::vector<Round2Response>>
OfflineParty::TryMakeRound2Responses(
    const std::vector<Round2Request>& requests_for_self) {
  if (round2_responses_done_) {
    TECDSA_THROW_LOGIC("MakeRound2Responses must not be called twice");
  }
  if (!round2_requests_done_) {
    TECDSA_THROW_LOGIC(
        "MakeRound2Requests must be completed before MakeRound2Responses");
  }

  try {
    mta::RequireExactlyOneRequestPerPeer(
        requests_for_self, peers_, cfg_.self_id, mta::MtaType::kMtAwc,
        std::identity{}, "SM2 offline request");
  } catch (const std::exception& ex) {
    return {.value = std::nullopt,
            .abort = detection::MakeAbort(
                detection::AbortStage::kOffline,
                detection::EvidenceKind::kMtaProof, cfg_.session_id,
                cfg_.self_id, ex.what())};
  }

  std::vector<Round2Response> out;
  out.reserve(requests_for_self.size());
  Scalar responder_sum = delta_responder_sum_;
  for (const auto& request : requests_for_self) {
    try {
      const auto consume = delta_session_.ResponderMidWithCheck(
          request,
          {.initiator_modulus_n =
               cfg_.public_keygen_data.all_paillier_public.at(request.from).n,
           .responder_aux =
               &cfg_.public_keygen_data.all_aux_rsa_params.at(cfg_.self_id),
           .initiator_aux =
               &cfg_.public_keygen_data.all_aux_rsa_params.at(request.from),
           .responder_secret = local_w_i_,
           .public_witness_point = local_W_i_});
      responder_sum = responder_sum + consume.responder_share;
      out.push_back(consume.response);
    } catch (const std::exception& ex) {
      return {.value = std::nullopt,
              .abort = detection::MakeAbort(
                  detection::AbortStage::kOffline,
                  detection::EvidenceKind::kMtaProof, cfg_.session_id,
                  cfg_.self_id, ex.what(), request.from, request.instance_id)};
    }
  }
  delta_responder_sum_ = responder_sum;
  round2_responses_done_ = true;
  return {.value = std::move(out), .abort = std::nullopt};
}

Round3Msg OfflineParty::MakeRound3(
    const std::vector<Round2Response>& responses_for_self) {
  if (round3_done_) {
    TECDSA_THROW_LOGIC("MakeRound3 must not be called twice");
  }
  if (!round2_responses_done_) {
    TECDSA_THROW_LOGIC("MakeRound2Responses must be completed before MakeRound3");
  }

  mta::RequireExactlyOneResponsePerInitiatorInstance(
      responses_for_self, peers_, peers_.size(), cfg_.self_id, delta_session_,
      std::identity{}, "SM2 offline response");
  for (const auto& response : responses_for_self) {
    const auto consume = delta_session_.InitiatorEndWithCheck(
        response,
        {.initiator_paillier = cfg_.local_key_share.paillier.get(),
         .initiator_aux = &cfg_.public_keygen_data.all_aux_rsa_params.at(cfg_.self_id),
         .public_witness_point = w_points_.at(response.from)});
    delta_initiator_sum_ = delta_initiator_sum_ + consume.initiator_share;
  }

  local_delta_i_ = (local_k_i_ * local_w_i_) + delta_initiator_sum_ +
                   delta_responder_sum_;
  local_T_i_ = ECPoint::GeneratorMultiply(local_delta_i_);
  local_WK_i_ = W_.Mul(local_k_i_);
  round3_done_ = true;
  return Round3Msg{
      .K_i = local_K_i_,
      .randomness = local_randomness_,
      .k_proof =
          proofs::BuildPiGroupProof(cfg_.session_id, cfg_.self_id, local_K_i_,
                                    local_k_i_),
      .T_i = local_T_i_,
      .t_proof =
          proofs::BuildPiGroupProof(cfg_.session_id, cfg_.self_id, local_T_i_,
                                    local_delta_i_),
      .WK_i = local_WK_i_,
      .wk_proof = proofs::BuildPiGroupRelationProof(
          cfg_.session_id, cfg_.self_id, W_, local_K_i_, local_WK_i_,
          local_k_i_),
  };
}

detection::DetectionResult<OfflineState> OfflineParty::TryFinalize(
    const PeerMap<Round3Msg>& peer_round3) {
  if (!round3_done_) {
    TECDSA_THROW_LOGIC("MakeRound3 must be completed before Finalize");
  }

  try {
    core::participant::RequireExactlyPeers(peer_round3, cfg_.participants,
                                           cfg_.self_id, "peer_round3");
  } catch (const std::exception& ex) {
    return {.value = std::nullopt,
            .abort = detection::MakeAbort(
                detection::AbortStage::kOffline,
                detection::EvidenceKind::kNonceProof, cfg_.session_id,
                cfg_.self_id, ex.what())};
  }
  std::vector<ECPoint> k_points;
  k_points.reserve(cfg_.participants.size());
  k_points.push_back(local_K_i_);
  PeerMap<ECPoint> all_t_points;
  all_t_points[cfg_.self_id] = local_T_i_;
  PeerMap<ECPoint> all_wk_points;
  all_wk_points[cfg_.self_id] = local_WK_i_;
  std::vector<ECPoint> t_points;
  t_points.reserve(cfg_.participants.size());
  t_points.push_back(local_T_i_);
  std::vector<ECPoint> wk_points;
  wk_points.reserve(cfg_.participants.size());
  wk_points.push_back(local_WK_i_);
  for (PartyIndex peer : peers_) {
    const auto& msg = peer_round3.at(peer);
    const auto commitment_it = phase1_commitments_.find(peer);
    if (commitment_it == phase1_commitments_.end()) {
      return {.value = std::nullopt,
              .abort = detection::MakeAbort(
                  detection::AbortStage::kOffline,
                  detection::EvidenceKind::kCommitment, cfg_.session_id,
                  cfg_.self_id, "missing phase1 commitment for peer")};
    }
    try {
      if (!core::commitment::VerifyCommitment(
              core::DefaultSm2Suite(), kPhase1CommitDomain,
              msg.K_i.ToCompressedBytes(), msg.randomness,
              commitment_it->second)) {
        return {.value = std::nullopt,
                .abort = detection::MakeAbort(
                    detection::AbortStage::kOffline,
                    detection::EvidenceKind::kCommitment, cfg_.session_id,
                    cfg_.self_id, "SM2 offline nonce opening verification failed", peer)};
      }
    } catch (const std::exception& ex) {
      return {.value = std::nullopt,
              .abort = detection::MakeAbort(
                  detection::AbortStage::kOffline,
                  detection::EvidenceKind::kCommitment, cfg_.session_id,
                  cfg_.self_id, ex.what(), peer)};
    }
    try {
      if (!proofs::VerifyPiGroupProof(cfg_.session_id, peer, msg.K_i,
                                      msg.k_proof)) {
        return {.value = std::nullopt,
                .abort = detection::MakeAbort(
                    detection::AbortStage::kOffline,
                    detection::EvidenceKind::kNonceProof, cfg_.session_id,
                    cfg_.self_id, "SM2 offline nonce pi_group verification failed", peer)};
      }
    } catch (const std::exception& ex) {
      return {.value = std::nullopt,
              .abort = detection::MakeAbort(
                  detection::AbortStage::kOffline,
                  detection::EvidenceKind::kNonceProof, cfg_.session_id,
                  cfg_.self_id, ex.what(), peer)};
    }
    try {
      if (!proofs::VerifyPiGroupProof(cfg_.session_id, peer, msg.T_i,
                                      msg.t_proof)) {
        return {.value = std::nullopt,
                .abort = detection::MakeAbort(
                    detection::AbortStage::kOffline,
                    detection::EvidenceKind::kNonceProof, cfg_.session_id,
                    cfg_.self_id, "SM2 offline delta proof verification failed", peer)};
      }
    } catch (const std::exception& ex) {
      return {.value = std::nullopt,
              .abort = detection::MakeAbort(
                  detection::AbortStage::kOffline,
                  detection::EvidenceKind::kNonceProof, cfg_.session_id,
                  cfg_.self_id, ex.what(), peer)};
    }
    try {
      if (!proofs::VerifyPiGroupRelationProof(cfg_.session_id, peer, W_,
                                              msg.K_i, msg.WK_i,
                                              msg.wk_proof)) {
        return {.value = std::nullopt,
                .abort = detection::MakeAbort(
                    detection::AbortStage::kOffline,
                    detection::EvidenceKind::kNonceProof, cfg_.session_id,
                    cfg_.self_id, "SM2 offline W^k relation proof verification failed", peer)};
      }
    } catch (const std::exception& ex) {
      return {.value = std::nullopt,
              .abort = detection::MakeAbort(
                  detection::AbortStage::kOffline,
                  detection::EvidenceKind::kNonceProof, cfg_.session_id,
                  cfg_.self_id, ex.what(), peer)};
    }
    k_points.push_back(msg.K_i);
    all_t_points[peer] = msg.T_i;
    all_wk_points[peer] = msg.WK_i;
    t_points.push_back(msg.T_i);
    wk_points.push_back(msg.WK_i);
  }

  try {
    if (internal::SumPointsOrThrow(t_points) != internal::SumPointsOrThrow(wk_points)) {
      return {.value = std::nullopt,
              .abort = detection::MakeAbort(
                  detection::AbortStage::kOffline,
                  detection::EvidenceKind::kNonceProof, cfg_.session_id,
                  cfg_.self_id, "SM2 offline product relation check failed")};
    }
  } catch (const std::exception& ex) {
    return {.value = std::nullopt,
            .abort = detection::MakeAbort(
                detection::AbortStage::kOffline,
                detection::EvidenceKind::kNonceProof, cfg_.session_id,
                cfg_.self_id,
                std::string("failed to aggregate SM2 offline relation points: ") +
                    ex.what())};
  }

  OfflineState offline;
  try {
    offline = OfflineState{
        .delta_i = local_delta_i_,
        .R = internal::SumPointsOrThrow(k_points),
        .W = W_,
        .all_W_i = w_points_,
        .all_T_i = std::move(all_t_points),
        .all_WK_i = std::move(all_wk_points),
    };
  } catch (const std::exception& ex) {
    return {.value = std::nullopt,
            .abort = detection::MakeAbort(
                detection::AbortStage::kOffline,
                detection::EvidenceKind::kNonceProof, cfg_.session_id,
                cfg_.self_id,
                std::string("failed to finalize SM2 offline presign: ") +
                    ex.what())};
  }
  return {.value = std::move(offline), .abort = std::nullopt};
}

}  // namespace tecdsa::sm2::presign
