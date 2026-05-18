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

#include <vector>

#include "yacl/crypto/experimental/threshold_signatures/common/errors.h"

namespace tecdsa::ecdsa::sign {

SignRound3Msg SignParty::MakeRound3(
    const std::vector<SignRound2Response>& responses_for_self) {
  if (state_.rounds.HasReached(SignStep::kRound3Done)) {
    TECDSA_THROW_LOGIC("MakeRound3 must not be called twice");
  }
  state_.rounds.RequireReached(
      SignStep::kRound2ResponsesDone,
      "MakeRound2Responses must be completed before MakeRound3");

  const Round2MtaSums initiator_sums = phase2_mta_.ConsumeResponses(
      responses_for_self, peers_, cfg_.local_key_share, verified_keygen_data_,
      w_points_);
  state_.round2.sums.delta_initiator = initiator_sums.delta_initiator;
  state_.round2.sums.sigma_initiator = initiator_sums.sigma_initiator;

  state_.round2.delta_i =
      (state_.round1.k_i * state_.round1.gamma_i) +
      state_.round2.sums.delta_initiator +
      state_.round2.sums.delta_responder;
  state_.round2.sigma_i =
      (state_.round1.k_i * local_w_i_) +
      state_.round2.sums.sigma_initiator +
      state_.round2.sums.sigma_responder;
  state_.rounds.Advance(SignStep::kRound2ResponsesDone, SignStep::kRound3Done,
                        "MakeRound3 must not be called twice");
  return SignRound3Msg{.delta_i = state_.round2.delta_i};
}

}  // namespace tecdsa::ecdsa::sign
