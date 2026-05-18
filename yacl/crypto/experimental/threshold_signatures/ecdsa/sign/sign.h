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

#pragma once

#include <memory>
#include <string>
#include <vector>

#include "yacl/crypto/experimental/threshold_signatures/ecdsa/keygen/messages.h"
#include "yacl/crypto/experimental/threshold_signatures/ecdsa/keygen/verified_data.h"
#include "yacl/crypto/experimental/threshold_signatures/ecdsa/sign/messages.h"
#include "yacl/crypto/experimental/threshold_signatures/ecdsa/sign/mta_exchange.h"
#include "yacl/crypto/experimental/threshold_signatures/ecdsa/sign/state.h"

namespace tecdsa::ecdsa::sign {

using LocalKeyShare = tecdsa::ecdsa::keygen::LocalKeyShare;
using PublicKeygenData = tecdsa::ecdsa::keygen::PublicKeygenData;

struct SignConfig {
  Bytes session_id;
  Bytes keygen_session_id;
  PartyIndex self_id = 0;
  std::vector<PartyIndex> participants;
  LocalKeyShare local_key_share;
  PublicKeygenData public_keygen_data;
  Bytes msg32;
};

class SignParty {
 public:
  explicit SignParty(SignConfig cfg);

  SignRound1Msg MakeRound1();
  std::vector<SignRound2Request> MakeRound2Requests(
      const PeerMap<SignRound1Msg>& peer_round1);
  std::vector<SignRound2Response> MakeRound2Responses(
      const std::vector<SignRound2Request>& requests_for_self);
  SignRound3Msg MakeRound3(
      const std::vector<SignRound2Response>& responses_for_self);
  SignRound4Msg MakeRound4(const PeerMap<SignRound3Msg>& peer_round3);
  SignRound5AMsg MakeRound5A(const PeerMap<SignRound4Msg>& peer_round4);
  SignRound5BMsg MakeRound5B(const PeerMap<SignRound5AMsg>& peer_round5a);
  SignRound5CMsg MakeRound5C(const PeerMap<SignRound5BMsg>& peer_round5b);
  SignRound5DMsg MakeRound5D(const PeerMap<SignRound5CMsg>& peer_round5c);
  Scalar RevealRound5E(const PeerMap<SignRound5DMsg>& peer_round5d);
  Signature Finalize(const PeerMap<Scalar>& peer_round5e);

 private:
  void PrepareResharedSigningShares();
  void EnsurePhase1Prepared();
  void EnsureRound5ASharePrepared();

  SignConfig cfg_;
  keygen::VerifiedPublicKeygenData verified_keygen_data_;
  std::vector<PartyIndex> peers_;
  SigningMtaExchange phase2_mta_;
  SigningState state_;

  Scalar message_scalar_;
  PeerMap<Scalar> lagrange_coefficients_;
  PeerMap<ECPoint> w_points_;
  Scalar local_w_i_;
};

}  // namespace tecdsa::ecdsa::sign
