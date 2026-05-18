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

#include <utility>
#include <vector>

#include "yacl/crypto/experimental/threshold_signatures/common/errors.h"
#include "yacl/crypto/experimental/threshold_signatures/core/protocol/message_store.h"
#include "yacl/crypto/experimental/threshold_signatures/ecdsa/sign/internal.h"

namespace tecdsa::ecdsa::sign {

std::vector<SignRound2Request> SignParty::MakeRound2Requests(
    const PeerMap<SignRound1Msg>& peer_round1) {
  if (state_.rounds.HasReached(SignStep::kRound2RequestsDone)) {
    TECDSA_THROW_LOGIC("MakeRound2Requests must not be called twice");
  }

  EnsurePhase1Prepared();
  core::protocol::RequireExactlyPeerMessages(peer_round1, peers_,
                                             "peer_round1");
  internal::StoreCommitments(peer_round1, peers_, &state_.round1.commitments,
                             "sign round1 commitment");

  std::vector<SignRound2Request> out = phase2_mta_.CreateRequests(
      peers_, cfg_.local_key_share, verified_keygen_data_,
      state_.round1.k_i);
  state_.rounds.Advance(SignStep::kRound1Done, SignStep::kRound2RequestsDone,
                        "MakeRound2Requests must not be called twice");
  return out;
}

std::vector<SignRound2Response> SignParty::MakeRound2Responses(
    const std::vector<SignRound2Request>& requests_for_self) {
  if (state_.rounds.HasReached(SignStep::kRound2ResponsesDone)) {
    TECDSA_THROW_LOGIC("MakeRound2Responses must not be called twice");
  }
  state_.rounds.RequireReached(
      SignStep::kRound2RequestsDone,
      "MakeRound2Requests must be completed before MakeRound2Responses");

  Round2ResponseBatch batch = phase2_mta_.ConsumeRequests(
      requests_for_self, peers_, verified_keygen_data_, state_.round1.gamma_i,
      local_w_i_, w_points_);
  state_.round2.sums.delta_responder = batch.sums.delta_responder;
  state_.round2.sums.sigma_responder = batch.sums.sigma_responder;
  state_.rounds.Advance(SignStep::kRound2RequestsDone,
                        SignStep::kRound2ResponsesDone,
                        "MakeRound2Responses must not be called twice");
  return std::move(batch.messages);
}

}  // namespace tecdsa::ecdsa::sign
