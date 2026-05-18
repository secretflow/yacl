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

#include "yacl/crypto/experimental/threshold_signatures/sm2/keygen/keygen.h"

#include <algorithm>
#include <exception>
#include <functional>
#include <string>
#include <utility>

#include "yacl/crypto/experimental/threshold_signatures/common/errors.h"
#include "yacl/crypto/experimental/threshold_signatures/core/keygen/round12_helpers.h"
#include "yacl/crypto/experimental/threshold_signatures/core/paillier/aux_proofs.h"
#include "yacl/crypto/experimental/threshold_signatures/core/paillier/paper_aux_proofs.h"
#include "yacl/crypto/experimental/threshold_signatures/core/paillier/paillier.h"
#include "yacl/crypto/experimental/threshold_signatures/core/participant/participant_set.h"
#include "yacl/crypto/experimental/threshold_signatures/sm2/common.h"
#include "yacl/crypto/experimental/threshold_signatures/sm2/detection/evidence.h"
#include "yacl/crypto/experimental/threshold_signatures/sm2/proofs/pi_group.h"

namespace tecdsa::sm2::keygen {
namespace {

namespace mta = tecdsa::core::mta;
namespace paillier = tecdsa::core::paillier;

constexpr uint32_t kMinPaillierKeygenBits = 2048;
constexpr uint32_t kMinAuxRsaKeygenBits = 164;
constexpr size_t kMaxPaillierKeygenAttempts = 32;
constexpr char kKeygenPhase1CommitDomain[] = "SM2/keygen/phase1";
constexpr char kDefaultSignerId[] = "1234567812345678";

}  // namespace

KeygenParty::KeygenParty(KeygenConfig cfg)
    : cfg_(std::move(cfg)),
      sigma_session_({.session_id = cfg_.session_id,
                      .self_id = cfg_.self_id,
                      .suite = core::DefaultSm2Suite(),
                      .group = internal::Sm2Group()}) {
  const auto participant_set = core::participant::BuildParticipantSet(
      cfg_.participants, cfg_.self_id, "sm2::keygen::KeygenParty");
  peers_ = participant_set.peers;
  if (cfg_.threshold >= cfg_.participants.size()) {
    TECDSA_THROW_ARGUMENT("threshold must be less than participant count");
  }
  if (cfg_.paillier_modulus_bits < kMinPaillierKeygenBits) {
    TECDSA_THROW_ARGUMENT("paillier_modulus_bits must be >= 2048");
  }
  if (cfg_.aux_rsa_modulus_bits < kMinAuxRsaKeygenBits) {
    TECDSA_THROW_ARGUMENT("aux_rsa_modulus_bits must be >= 164");
  }
  if (cfg_.signer_id.empty()) {
    cfg_.signer_id.assign(kDefaultSignerId,
                          kDefaultSignerId + sizeof(kDefaultSignerId) - 1);
  }
  local_z_i_ = internal::Sm2Zero();
  local_secret_z_i_ = internal::Sm2Zero();
  local_gamma_i_ = internal::Sm2Zero();
  sigma_initiator_sum_ = internal::Sm2Zero();
  sigma_responder_sum_ = internal::Sm2Zero();
  local_sigma_i_ = internal::Sm2Zero();
}

void KeygenParty::EnsureLocalPolynomialPrepared() {
  if (!local_poly_coefficients_.empty()) {
    return;
  }

  auto prepared = core::keygen::PrepareLocalRound1Bundle(
      cfg_.participants, cfg_.threshold, core::DefaultSm2Suite(),
      kKeygenPhase1CommitDomain, []() { return internal::RandomNonZeroSm2Scalar(); },
      [](const std::vector<Scalar>& coefficients, PartyIndex party) {
        return internal::EvaluatePolynomialAt(coefficients, party);
      },
      [](const std::vector<Scalar>& coefficients) {
        return internal::BuildCommitments(coefficients);
      });
  local_poly_coefficients_ = std::move(prepared.coefficients);
  local_shares_ = std::move(prepared.shares);
  local_vss_commitments_ = std::move(prepared.commitments);
  local_Z_i_ = prepared.public_point;
  local_secret_z_i_ = local_poly_coefficients_.front();
  local_commitment_ = std::move(prepared.commitment);
  local_open_randomness_ = std::move(prepared.randomness);
}

void KeygenParty::EnsureLocalPaillierAndAuxPrepared() {
  if (local_aux_rsa_params_.n_tilde > 0) {
    return;
  }

  auto prepared = core::keygen::PrepareLocalPaillierAuxBundle(
      cfg_.paillier_modulus_bits, cfg_.aux_rsa_modulus_bits,
      kMaxPaillierKeygenAttempts, cfg_.session_id, cfg_.self_id,
      core::DefaultSm2Suite(), internal::Sm2Group());
  local_paillier_ = std::move(prepared.paillier);
  local_paillier_public_ = prepared.paillier_public;
  local_aux_rsa_params_ = prepared.aux_rsa_params;
  local_aux_rsa_witness_ = prepared.aux_rsa_witness;
  local_aux_param_proof_ = prepared.aux_param_proof;
}

void KeygenParty::EnsureLocalProofsPrepared() {
  if (!local_square_free_proof_.blob.empty()) {
    return;
  }

  EnsureLocalPaillierAndAuxPrepared();
  const auto context =
      paillier::BuildProofContext(cfg_.session_id, cfg_.self_id,
                                  core::DefaultSm2Suite(), internal::Sm2Group());
  local_square_free_proof_ = paillier::BuildSquareFreeProofGmr98(
      local_paillier_public_.n, local_paillier_->private_lambda_bigint(),
      context);
}

KeygenRound1Msg KeygenParty::MakeRound1() {
  EnsureLocalPolynomialPrepared();
  EnsureLocalProofsPrepared();

  all_phase1_commitments_[cfg_.self_id] = local_commitment_;
  all_paillier_public_[cfg_.self_id] = local_paillier_public_;
  all_aux_rsa_params_[cfg_.self_id] = local_aux_rsa_params_;
  all_aux_param_proofs_[cfg_.self_id] = local_aux_param_proof_;

  return KeygenRound1Msg{
      .commitment = local_commitment_,
      .paillier_public = local_paillier_public_,
      .aux_rsa_params = local_aux_rsa_params_,
      .aux_param_proof = local_aux_param_proof_,
  };
}

KeygenRound2Out KeygenParty::MakeRound2(
    const PeerMap<KeygenRound1Msg>& peer_round1) {
  (void)MakeRound1();
  core::participant::RequireExactlyPeers(peer_round1, cfg_.participants,
                                         cfg_.self_id, "peer_round1");

  for (PartyIndex peer : peers_) {
    const auto& msg = peer_round1.at(peer);
    core::keygen::ValidatePeerRound1Common(
        cfg_.session_id, peer, core::DefaultSm2Suite(), internal::Sm2Group(),
        msg.paillier_public, msg.aux_rsa_params, msg.aux_param_proof);

    all_phase1_commitments_[peer] = msg.commitment;
    all_paillier_public_[peer] = msg.paillier_public;
    all_aux_rsa_params_[peer] = msg.aux_rsa_params;
    all_aux_param_proofs_[peer] = msg.aux_param_proof;
  }

  KeygenRound2Out out;
  out.broadcast = KeygenRound2Broadcast{
      .Z_i = local_Z_i_,
      .randomness = local_open_randomness_,
      .commitments = local_vss_commitments_,
  };
  for (PartyIndex peer : peers_) {
    out.shares_for_peers.emplace(peer, local_shares_.at(peer));
  }
  round2_done_ = true;
  return out;
}

std::vector<KeygenRound3Request> KeygenParty::MakeRound3Requests(
    const PeerMap<KeygenRound2Broadcast>& peer_round2,
    const PeerMap<Scalar>& shares_for_self) {
  if (round3_requests_done_) {
    TECDSA_THROW_LOGIC("MakeRound3Requests must not be called twice");
  }
  if (!round2_done_) {
    TECDSA_THROW_LOGIC("MakeRound2 must be completed before MakeRound3Requests");
  }

  core::participant::RequireExactlyPeers(peer_round2, cfg_.participants,
                                         cfg_.self_id, "peer_round2");
  core::participant::RequireExactlyPeers(shares_for_self, cfg_.participants,
                                         cfg_.self_id, "shares_for_self");

  Scalar z_sum = local_shares_.at(cfg_.self_id);
  for (PartyIndex peer : peers_) {
    const auto& msg = peer_round2.at(peer);
    const auto commitment_it = all_phase1_commitments_.find(peer);
    if (commitment_it == all_phase1_commitments_.end()) {
      TECDSA_THROW_LOGIC("missing stored round1 commitment for peer");
    }
    const Scalar share = shares_for_self.at(peer);
    core::keygen::ValidatePeerRound2ShareCommon(
        cfg_.threshold, core::DefaultSm2Suite(), kKeygenPhase1CommitDomain,
        "Z_i", commitment_it->second, msg.Z_i, msg.randomness, msg.commitments,
        share, [this](const std::vector<ECPoint>& commitments,
                      const Scalar& candidate_share) {
          return internal::VerifyShareForReceiver(
              cfg_.self_id, cfg_.threshold, commitments, candidate_share);
        });
    z_sum = z_sum + share;
  }

  if (z_sum.value() == 0) {
    TECDSA_THROW_ARGUMENT("aggregated local z share is zero");
  }

  local_z_i_ = z_sum;
  local_Y_i_ = ECPoint::GeneratorMultiply(local_z_i_);
  local_gamma_i_ = internal::RandomNonZeroSm2Scalar();
  local_Gamma_i_ = ECPoint::GeneratorMultiply(local_gamma_i_);
  std::vector<ECPoint> z_points;
  z_points.reserve(cfg_.participants.size());
  z_points.push_back(local_Z_i_);
  for (PartyIndex peer : peers_) {
    z_points.push_back(peer_round2.at(peer).Z_i);
  }
  global_Z_ = internal::SumPointsOrThrow(z_points);
  local_ZGamma_i_ = global_Z_.Mul(local_gamma_i_);

  std::vector<KeygenRound3Request> out;
  out.reserve(peers_.size());
  for (PartyIndex peer : peers_) {
    out.push_back(sigma_session_.InitiatorInit({
        .responder_id = peer,
        .initiator_paillier = local_paillier_.get(),
        .responder_aux = &all_aux_rsa_params_.at(peer),
        .initiator_secret = local_gamma_i_,
    }));
  }
  round3_requests_done_ = true;
  return out;
}

detection::DetectionResult<std::vector<KeygenRound3Response>>
KeygenParty::TryMakeRound3Responses(
    const std::vector<KeygenRound3Request>& requests_for_self) {
  if (round3_responses_done_) {
    TECDSA_THROW_LOGIC("MakeRound3Responses must not be called twice");
  }
  if (!round3_requests_done_) {
    TECDSA_THROW_LOGIC(
        "MakeRound3Requests must be completed before MakeRound3Responses");
  }

  try {
    mta::RequireExactlyOneRequestPerPeer(
        requests_for_self, peers_, cfg_.self_id, mta::MtaType::kMta,
        std::identity{}, "SM2 keygen request");
  } catch (const std::exception& ex) {
    return {.value = std::nullopt,
            .abort = detection::MakeAbort(
                detection::AbortStage::kKeygen,
                detection::EvidenceKind::kMtaProof, cfg_.session_id,
                cfg_.self_id, ex.what())};
  }

  std::vector<KeygenRound3Response> out;
  out.reserve(requests_for_self.size());
  Scalar responder_sum = sigma_responder_sum_;
  for (const auto& request : requests_for_self) {
    try {
      const auto consume = sigma_session_.ResponderMid(
          request,
          {.initiator_modulus_n = all_paillier_public_.at(request.from).n,
           .responder_aux = &all_aux_rsa_params_.at(cfg_.self_id),
           .initiator_aux = &all_aux_rsa_params_.at(request.from),
           .responder_secret = local_secret_z_i_});
      responder_sum = responder_sum + consume.responder_share;
      out.push_back(consume.response);
    } catch (const std::exception& ex) {
      return {.value = std::nullopt,
              .abort = detection::MakeAbort(
                  detection::AbortStage::kKeygen,
                  detection::EvidenceKind::kMtaProof, cfg_.session_id,
                  cfg_.self_id, ex.what(), request.from, request.instance_id)};
    }
  }

  sigma_responder_sum_ = responder_sum;
  round3_responses_done_ = true;
  return {.value = std::move(out), .abort = std::nullopt};
}

KeygenRound4Msg KeygenParty::MakeRound4(
    const std::vector<KeygenRound3Response>& responses_for_self) {
  if (round4_done_) {
    TECDSA_THROW_LOGIC("MakeRound4 must not be called twice");
  }
  if (!round3_responses_done_) {
    TECDSA_THROW_LOGIC("MakeRound3Responses must be completed before MakeRound4");
  }

  mta::RequireExactlyOneResponsePerInitiatorInstance(
      responses_for_self, peers_, peers_.size(), cfg_.self_id, sigma_session_,
      std::identity{}, "SM2 keygen response");

  for (const auto& response : responses_for_self) {
    const auto consume = sigma_session_.InitiatorEnd(
        response,
        {.initiator_paillier = local_paillier_.get(),
         .initiator_aux = &all_aux_rsa_params_.at(cfg_.self_id)});
    sigma_initiator_sum_ = sigma_initiator_sum_ + consume.initiator_share;
  }

  local_sigma_i_ = (local_gamma_i_ * local_secret_z_i_) +
                   sigma_initiator_sum_ + sigma_responder_sum_;
  round4_done_ = true;
  return KeygenRound4Msg{
      .sigma_i = local_sigma_i_,
      .Y_i = local_Y_i_,
      .y_proof =
          proofs::BuildPiGroupProof(cfg_.session_id, cfg_.self_id, local_Y_i_,
                                    local_z_i_),
      .Gamma_i = local_Gamma_i_,
      .ZGamma_i = local_ZGamma_i_,
      .gamma_proof = proofs::BuildPiGroupRelationProof(
          cfg_.session_id, cfg_.self_id, global_Z_, local_Gamma_i_,
          local_ZGamma_i_, local_gamma_i_),
      .square_free_proof = local_square_free_proof_,
  };
}

detection::DetectionResult<KeygenOutput> KeygenParty::TryFinalize(
    const PeerMap<KeygenRound4Msg>& peer_round4) {
  if (!round4_done_) {
    TECDSA_THROW_LOGIC("MakeRound4 must be completed before Finalize");
  }

  try {
    core::participant::RequireExactlyPeers(peer_round4, cfg_.participants,
                                           cfg_.self_id, "peer_round4");
  } catch (const std::exception& ex) {
    return {.value = std::nullopt,
            .abort = detection::MakeAbort(
                detection::AbortStage::kKeygen,
                detection::EvidenceKind::kGammaProof, cfg_.session_id,
                cfg_.self_id, ex.what())};
  }

  Scalar sigma = local_sigma_i_;
  std::vector<ECPoint> gamma_points;
  gamma_points.reserve(cfg_.participants.size());
  gamma_points.push_back(local_Gamma_i_);

  PublicKeygenData public_data;
  public_data.threshold = cfg_.threshold;
  public_data.all_Y_i[cfg_.self_id] = local_Y_i_;
  public_data.all_paillier_public = all_paillier_public_;
  public_data.all_aux_rsa_params = all_aux_rsa_params_;
  public_data.all_aux_param_proofs = all_aux_param_proofs_;
  public_data.all_square_free_proofs[cfg_.self_id] = local_square_free_proof_;

  for (PartyIndex peer : peers_) {
    const auto& msg = peer_round4.at(peer);
    try {
      if (!proofs::VerifyPiGroupProof(cfg_.session_id, peer, msg.Y_i,
                                      msg.y_proof)) {
        return {.value = std::nullopt,
                .abort = detection::MakeAbort(
                    detection::AbortStage::kKeygen,
                    detection::EvidenceKind::kGammaProof, cfg_.session_id,
                    cfg_.self_id, "peer y share proof verification failed", peer)};
      }
    } catch (const std::exception& ex) {
      return {.value = std::nullopt,
              .abort = detection::MakeAbort(
                  detection::AbortStage::kKeygen,
                  detection::EvidenceKind::kGammaProof, cfg_.session_id,
                  cfg_.self_id, ex.what(), peer)};
    }
    try {
      if (!proofs::VerifyPiGroupRelationProof(cfg_.session_id, peer, global_Z_,
                                              msg.Gamma_i, msg.ZGamma_i,
                                              msg.gamma_proof)) {
        return {.value = std::nullopt,
                .abort = detection::MakeAbort(
                    detection::AbortStage::kKeygen,
                    detection::EvidenceKind::kGammaProof, cfg_.session_id,
                    cfg_.self_id, "peer gamma proof verification failed", peer)};
      }
    } catch (const std::exception& ex) {
      return {.value = std::nullopt,
              .abort = detection::MakeAbort(
                  detection::AbortStage::kKeygen,
                  detection::EvidenceKind::kGammaProof, cfg_.session_id,
                  cfg_.self_id, ex.what(), peer)};
    }
    const auto context =
        paillier::BuildProofContext(cfg_.session_id, peer,
                                    core::DefaultSm2Suite(),
                                    internal::Sm2Group());
    try {
      if (!paillier::VerifySquareFreeProofGmr98(
              all_paillier_public_.at(peer).n, msg.square_free_proof,
              context)) {
        return {.value = std::nullopt,
                .abort = detection::MakeAbort(
                    detection::AbortStage::kKeygen,
                    detection::EvidenceKind::kSquareFreeProof, cfg_.session_id,
                    cfg_.self_id, "peer pi_sqr proof verification failed", peer)};
      }
    } catch (const std::exception& ex) {
      return {.value = std::nullopt,
              .abort = detection::MakeAbort(
                  detection::AbortStage::kKeygen,
                  detection::EvidenceKind::kSquareFreeProof, cfg_.session_id,
                  cfg_.self_id, ex.what(), peer)};
    }

    sigma = sigma + msg.sigma_i;
    public_data.all_Y_i[peer] = msg.Y_i;
    gamma_points.push_back(msg.Gamma_i);
    public_data.all_square_free_proofs[peer] = msg.square_free_proof;
  }

  if (sigma.value() == 0) {
    return {.value = std::nullopt,
            .abort = detection::MakeAbort(
                detection::AbortStage::kKeygen,
                detection::EvidenceKind::kGammaProof, cfg_.session_id,
                cfg_.self_id, "aggregated sigma is zero")};
  }
  const Scalar sigma_inverse = sigma.InverseModQ();
  public_data.sigma_inverse = sigma_inverse;

  ECPoint plus_one_public;
  try {
    for (PartyIndex party : cfg_.participants) {
      const ECPoint gamma_point =
          (party == cfg_.self_id) ? local_Gamma_i_ : peer_round4.at(party).Gamma_i;
      public_data.all_plus_one_public_shares[party] = gamma_point.Mul(sigma_inverse);
    }
    std::vector<ECPoint> plus_one_points;
    plus_one_points.reserve(cfg_.participants.size());
    for (PartyIndex party : cfg_.participants) {
      plus_one_points.push_back(public_data.all_plus_one_public_shares.at(party));
    }
    plus_one_public = internal::SumPointsOrThrow(plus_one_points);
    public_data.public_key =
        plus_one_public.Add(ECPoint::GeneratorMultiply(internal::Sm2Negate(
            internal::Sm2One())));
  } catch (const std::exception& ex) {
    return {.value = std::nullopt,
            .abort = detection::MakeAbort(
                detection::AbortStage::kKeygen,
                detection::EvidenceKind::kGammaProof, cfg_.session_id,
                cfg_.self_id,
                std::string("failed to derive SM2 public key: ") + ex.what())};
  }

  if (public_data.public_key == plus_one_public) {
    return {.value = std::nullopt,
            .abort = detection::MakeAbort(
                detection::AbortStage::kKeygen,
                detection::EvidenceKind::kGammaProof, cfg_.session_id,
                cfg_.self_id, "invalid SM2 public key derivation")};
  }

  zid::IdentityBinding binding =
      zid::BindIdentity(cfg_.signer_id, public_data.public_key);

  KeygenOutput output{
      .local_key_share =
          LocalKeyShare{
              .z_i = local_z_i_,
              .paillier = local_paillier_,
              .binding = std::move(binding),
      },
      .public_keygen_data = std::move(public_data),
  };
  return {.value = std::move(output), .abort = std::nullopt};
}

}  // namespace tecdsa::sm2::keygen
