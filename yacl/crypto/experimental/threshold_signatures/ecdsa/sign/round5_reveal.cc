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
#include "yacl/crypto/experimental/threshold_signatures/core/protocol/message_store.h"
#include "yacl/crypto/experimental/threshold_signatures/core/vss/dealerless_dkg.h"
#include "yacl/crypto/experimental/threshold_signatures/ecdsa/sign/internal.h"
#include "yacl/crypto/experimental/threshold_signatures/ecdsa/sign/relation_proofs.h"

namespace tecdsa::ecdsa::sign {
namespace {

namespace relation = tecdsa::ecdsa::sign;

}  // namespace

Scalar SignParty::RevealRound5E(
    const PeerMap<SignRound5DMsg>& peer_round5d) {
  if (state_.rounds.HasReached(SignStep::kRound5EDone)) {
    TECDSA_THROW_LOGIC("RevealRound5E must not be called twice");
  }
  state_.rounds.RequireReached(
      SignStep::kRound5DDone,
      "MakeRound5D must be completed before RevealRound5E");

  core::protocol::RequireExactlyPeerMessages(peer_round5d, peers_,
                                             "peer_round5d");
  std::vector<ECPoint> u_points;
  std::vector<ECPoint> t_points;
  u_points.reserve(cfg_.participants.size());
  t_points.reserve(cfg_.participants.size());
  u_points.push_back(state_.consistency.U_i);
  t_points.push_back(state_.consistency.T_i);

  for (PartyIndex peer : peers_) {
    const SignRound5DMsg& msg = peer_round5d.at(peer);
    const auto commitment_it =
        state_.consistency.round5c_commitments.find(peer);
    if (commitment_it == state_.consistency.round5c_commitments.end()) {
      TECDSA_THROW_LOGIC("missing stored round5C commitment for peer");
    }
    if (!core::commitment::VerifyCommitment(
            core::DefaultEcdsaSuite(), internal::kPhase5CCommitDomain,
            relation::SerializePointPair(msg.U_i, msg.T_i), msg.randomness,
            commitment_it->second)) {
      TECDSA_THROW_ARGUMENT(
          "round5D opening does not match round5C commitment");
    }
    u_points.push_back(msg.U_i);
    t_points.push_back(msg.T_i);
  }

  try {
    const ECPoint sum_u = core::vss::SumPointsOrThrow(u_points);
    const ECPoint sum_t = core::vss::SumPointsOrThrow(t_points);
    if (sum_u != sum_t) {
      TECDSA_THROW_ARGUMENT("round5D consistency check failed");
    }
  } catch (const std::exception& ex) {
    TECDSA_THROW_ARGUMENT(std::string("failed to validate round5D: ") +
                          ex.what());
  }

  state_.rounds.Advance(SignStep::kRound5DDone, SignStep::kRound5EDone,
                        "RevealRound5E must not be called twice");
  return state_.final_share.s_i;
}

}  // namespace tecdsa::ecdsa::sign
