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
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "yacl/crypto/experimental/threshold_ecdsa/protocol/messages.h"
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/proto_common.h"

namespace tecdsa::proto {

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

  const SignConfig& config() const;

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
  struct Phase2InitiatorInstance {
    PartyIndex responder = 0;
    MtaType type = MtaType::kTimesGamma;
    Bytes instance_id;
    BigInt c1 = BigInt(0);
  };

  void PrepareResharedSigningShares();
  void EnsurePhase1Prepared();
  void EnsureRound5ASharePrepared();

  SignConfig cfg_;
  std::vector<PartyIndex> peers_;

  Scalar message_scalar_;
  PeerMap<Scalar> lagrange_coefficients_;
  PeerMap<ECPoint> w_points_;
  Scalar local_w_i_;

  Scalar local_k_i_;
  Scalar local_gamma_i_;
  ECPoint local_Gamma_i_;
  Bytes local_round1_randomness_;
  PeerMap<Bytes> phase1_commitments_;
  std::unordered_map<std::string, Phase2InitiatorInstance>
      phase2_initiator_instances_;
  std::vector<SignRound2Request> round2_requests_;
  std::optional<std::vector<SignRound2Response>> round2_responses_;
  Scalar phase2_mta_initiator_sum_;
  Scalar phase2_mta_responder_sum_;
  Scalar phase2_mtawc_initiator_sum_;
  Scalar phase2_mtawc_responder_sum_;
  Scalar local_delta_i_;
  Scalar local_sigma_i_;
  Scalar delta_inv_;
  ECPoint gamma_;
  ECPoint R_;
  Scalar r_;
  Scalar local_s_i_;
  Scalar local_l_i_;
  Scalar local_rho_i_;
  ECPoint local_V_i_;
  ECPoint local_A_i_;
  Bytes local_round5a_randomness_;
  PeerMap<Bytes> phase5a_commitments_;
  ECPoint V_;
  ECPoint A_;
  ECPoint local_U_i_;
  ECPoint local_T_i_;
  Bytes local_round5c_randomness_;
  PeerMap<Bytes> phase5c_commitments_;

  std::optional<SignRound1Msg> round1_;
  std::optional<SignRound3Msg> round3_;
  std::optional<SignRound4Msg> round4_;
  std::optional<SignRound5AMsg> round5a_;
  std::optional<SignRound5BMsg> round5b_;
  std::optional<SignRound5CMsg> round5c_;
  std::optional<SignRound5DMsg> round5d_;
  std::optional<Scalar> round5e_;
  std::optional<Signature> signature_;
};

}  // namespace tecdsa::proto
