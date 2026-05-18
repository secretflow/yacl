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
#include <utility>
#include <vector>

#include "yacl/crypto/experimental/threshold_signatures/common/errors.h"
#include "yacl/crypto/experimental/threshold_signatures/core/commitment/commitment.h"
#include "yacl/crypto/experimental/threshold_signatures/core/participant/participant_set.h"
#include "yacl/crypto/experimental/threshold_signatures/core/vss/dealerless_dkg.h"
#include "yacl/crypto/experimental/threshold_signatures/core/vss/feldman.h"
#include "yacl/crypto/experimental/threshold_signatures/ecdsa/sign/internal.h"
#include "yacl/crypto/experimental/threshold_signatures/ecdsa/sign/relation_proofs.h"

namespace tecdsa::ecdsa::sign {
namespace {

namespace keygen = tecdsa::ecdsa::keygen;
namespace relation = tecdsa::ecdsa::sign;

}  // namespace

SignParty::SignParty(SignConfig cfg)
    : cfg_(std::move(cfg)),
      phase2_mta_({.session_id = cfg_.session_id,
                   .self_id = cfg_.self_id,
                   .suite = core::DefaultEcdsaSuite(),
                   .group = nullptr}),
      message_scalar_(Scalar::FromBigEndianModQ(cfg_.msg32)) {
  const auto participant_set = core::participant::BuildParticipantSet(
      cfg_.participants, cfg_.self_id, "ecdsa::sign::SignParty");
  peers_ = participant_set.peers;
  if (cfg_.participants.size() !=
      static_cast<size_t>(cfg_.public_keygen_data.threshold) + 1) {
    TECDSA_THROW_ARGUMENT("signer set size must equal threshold + 1");
  }
  if (cfg_.msg32.size() != 32) {
    TECDSA_THROW_ARGUMENT("msg32 must be exactly 32 bytes for SignParty");
  }
  if (cfg_.local_key_share.x_i.value() == 0) {
    TECDSA_THROW_ARGUMENT("local x_i share must be non-zero");
  }
  if (cfg_.local_key_share.paillier == nullptr) {
    TECDSA_THROW_ARGUMENT("local Paillier provider must be present");
  }
  if (ECPoint::GeneratorMultiply(cfg_.local_key_share.x_i) !=
      cfg_.local_key_share.X_i) {
    TECDSA_THROW_ARGUMENT("local key share X_i does not match x_i");
  }

  verified_keygen_data_ = keygen::VerifiedPublicKeygenData::Create(
      cfg_.public_keygen_data, cfg_.keygen_session_id,
      core::DefaultEcdsaSuite(), cfg_.local_key_share.x_i.group(),
      cfg_.participants, cfg_.self_id, cfg_.local_key_share);

  PrepareResharedSigningShares();
}

void SignParty::PrepareResharedSigningShares() {
  lagrange_coefficients_ = core::vss::ComputeLagrangeAtZero(
      cfg_.participants, cfg_.local_key_share.x_i.group());

  const auto lambda_self_it = lagrange_coefficients_.find(cfg_.self_id);
  if (lambda_self_it == lagrange_coefficients_.end()) {
    TECDSA_THROW_ARGUMENT("missing lagrange coefficient for self");
  }

  local_w_i_ = lambda_self_it->second * cfg_.local_key_share.x_i;

  std::vector<ECPoint> w_points;
  w_points.reserve(cfg_.participants.size());
  for (PartyIndex party : cfg_.participants) {
    const auto lambda_it = lagrange_coefficients_.find(party);
    if (lambda_it == lagrange_coefficients_.end()) {
      TECDSA_THROW_ARGUMENT("missing lagrange coefficient for participant");
    }

    try {
      w_points_[party] = verified_keygen_data_.XOf(party).Mul(lambda_it->second);
    } catch (const std::exception& ex) {
      TECDSA_THROW_ARGUMENT(std::string("failed to compute W_i: ") + ex.what());
    }
    w_points.push_back(w_points_.at(party));
  }

  try {
    const ECPoint reconstructed_y = core::vss::SumPointsOrThrow(w_points);
    if (reconstructed_y != verified_keygen_data_.raw().y) {
      TECDSA_THROW_ARGUMENT("W_i aggregation does not reconstruct y");
    }
  } catch (const std::exception& ex) {
    TECDSA_THROW_ARGUMENT(std::string("failed to validate W_i aggregation: ") +
                          ex.what());
  }
}

void SignParty::EnsurePhase1Prepared() {
  if (state_.rounds.HasReached(SignStep::kRound1Done)) {
    return;
  }

  const auto& group = cfg_.local_key_share.x_i.group();
  state_.round1.k_i = core::vss::RandomNonZeroScalar(group);
  state_.round1.gamma_i = core::vss::RandomNonZeroScalar(group);
  state_.round1.Gamma_i = ECPoint::GeneratorMultiply(state_.round1.gamma_i);

  const core::commitment::CommitmentResult commit =
      core::commitment::CommitMessage(
          core::DefaultEcdsaSuite(), internal::kPhase1CommitDomain,
          state_.round1.Gamma_i.ToCompressedBytes());
  state_.round1.randomness = commit.randomness;
  state_.round1.commitments[cfg_.self_id] = commit.commitment;
  state_.rounds.Advance(SignStep::kInit, SignStep::kRound1Done,
                        "MakeRound1 must not be called twice");
}

void SignParty::EnsureRound5ASharePrepared() {
  if (state_.rounds.HasReached(SignStep::kRound5ADone)) {
    return;
  }

  state_.final_share.s_i =
      (message_scalar_ * state_.round1.k_i) +
      (state_.delta.r * state_.round2.sigma_i);
  const auto& group = cfg_.local_key_share.x_i.group();
  state_.final_share.l_i = core::vss::RandomNonZeroScalar(group);
  state_.final_share.rho_i = core::vss::RandomNonZeroScalar(group);

  state_.final_share.V_i = ECPoint::GeneratorMultiply(state_.final_share.l_i);
  if (state_.final_share.s_i.value() != 0) {
    state_.final_share.V_i =
        state_.final_share.V_i.Add(state_.delta.R.Mul(state_.final_share.s_i));
  }
  state_.final_share.A_i = ECPoint::GeneratorMultiply(state_.final_share.rho_i);

  const core::commitment::CommitmentResult commit =
      core::commitment::CommitMessage(
          core::DefaultEcdsaSuite(), internal::kPhase5ACommitDomain,
          relation::SerializePointPair(state_.final_share.V_i,
                                       state_.final_share.A_i));
  state_.final_share.round5a_randomness = commit.randomness;
  state_.final_share.round5a_commitments[cfg_.self_id] = commit.commitment;
  state_.rounds.Advance(SignStep::kRound4Done, SignStep::kRound5ADone,
                        "MakeRound5A must not be called twice");
}

}  // namespace tecdsa::ecdsa::sign
