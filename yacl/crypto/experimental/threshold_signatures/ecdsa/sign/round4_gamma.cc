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

#include <optional>

#include "yacl/crypto/experimental/threshold_signatures/common/errors.h"
#include "yacl/crypto/experimental/threshold_signatures/core/proof/schnorr.h"
#include "yacl/crypto/experimental/threshold_signatures/core/protocol/message_store.h"
#include "yacl/crypto/experimental/threshold_signatures/ecdsa/sign/internal.h"

namespace tecdsa::ecdsa::sign {

SignRound4Msg SignParty::MakeRound4(
    const PeerMap<SignRound3Msg>& peer_round3) {
  if (state_.rounds.HasReached(SignStep::kRound4Done)) {
    TECDSA_THROW_LOGIC("MakeRound4 must not be called twice");
  }
  state_.rounds.RequireReached(SignStep::kRound3Done,
                               "MakeRound3 must be completed before MakeRound4");

  core::protocol::RequireExactlyPeerMessages(peer_round3, peers_,
                                             "peer_round3");
  Scalar delta = state_.round2.delta_i;
  for (PartyIndex peer : peers_) {
    delta = delta + peer_round3.at(peer).delta_i;
  }
  if (delta.value() == 0) {
    TECDSA_THROW_ARGUMENT("aggregated delta is zero");
  }

  const std::optional<Scalar> delta_inv = internal::InvertScalar(delta);
  if (!delta_inv.has_value()) {
    TECDSA_THROW_ARGUMENT("failed to invert aggregated delta");
  }
  state_.delta.delta_inv = *delta_inv;

  state_.rounds.Advance(SignStep::kRound3Done, SignStep::kRound4Done,
                        "MakeRound4 must not be called twice");
  return SignRound4Msg{
      .gamma_i = state_.round1.Gamma_i,
      .randomness = state_.round1.randomness,
      .gamma_proof = core::proof::BuildSchnorrProof(
          core::DefaultEcdsaSuite(), cfg_.session_id, cfg_.self_id,
          state_.round1.Gamma_i, state_.round1.gamma_i),
  };
}

}  // namespace tecdsa::ecdsa::sign
