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

#include "yacl/crypto/experimental/threshold_signatures/common/errors.h"
#include "yacl/crypto/experimental/threshold_signatures/core/protocol/message_store.h"
#include "yacl/crypto/experimental/threshold_signatures/ecdsa/verify/verify.h"

namespace tecdsa::ecdsa::sign {
namespace {

namespace verify = tecdsa::ecdsa::verify;

}  // namespace

Signature SignParty::Finalize(const PeerMap<Scalar>& peer_round5e) {
  state_.rounds.RequireReached(SignStep::kRound5EDone,
                               "RevealRound5E must be completed before Finalize");

  core::protocol::RequireExactlyPeerMessages(peer_round5e, peers_,
                                             "peer_round5e");
  Scalar s = state_.final_share.s_i;
  for (PartyIndex peer : peers_) {
    s = s + peer_round5e.at(peer);
  }
  if (s.value() == 0) {
    TECDSA_THROW_ARGUMENT("aggregated signature scalar s is zero");
  }

  if (!verify::VerifyEcdsaSignatureMath(verified_keygen_data_.raw().y,
                                        cfg_.msg32, state_.delta.r, s)) {
    TECDSA_THROW_ARGUMENT("final ECDSA signature verification failed");
  }

  return Signature{
      .r = state_.delta.r,
      .s = s,
      .R = state_.delta.R,
  };
}

}  // namespace tecdsa::ecdsa::sign
