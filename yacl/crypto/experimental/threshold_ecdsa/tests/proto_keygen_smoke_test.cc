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

#include <iostream>
#include <stdexcept>
#include <unordered_map>
#include <vector>

#include "yacl/crypto/experimental/threshold_ecdsa/protocol/keygen.h"

namespace {

void Expect(bool condition, const std::string& message) {
  if (!condition) {
    throw std::runtime_error("Test failed: " + message);
  }
}

void RunThreePartyKeygenSmoke() {
  using tecdsa::PartyIndex;
  using tecdsa::proto::KeygenConfig;
  using tecdsa::proto::KeygenOutput;
  using tecdsa::proto::KeygenParty;
  using tecdsa::proto::KeygenRound1Msg;
  using tecdsa::proto::KeygenRound2Broadcast;
  using tecdsa::proto::PeerMap;

  const std::vector<PartyIndex> participants = {1, 2, 3};
  std::unordered_map<PartyIndex, KeygenParty> parties;
  for (PartyIndex party : participants) {
    KeygenConfig cfg;
    cfg.session_id = {0x10, 0x20, 0x30};
    cfg.self_id = party;
    cfg.participants = participants;
    cfg.threshold = 1;
    parties.emplace(party, KeygenParty(std::move(cfg)));
  }

  std::unordered_map<PartyIndex, KeygenRound1Msg> round1;
  for (PartyIndex party : participants) {
    round1.emplace(party, parties.at(party).MakeRound1());
  }

  std::unordered_map<PartyIndex, KeygenRound2Broadcast> round2_broadcasts;
  std::unordered_map<PartyIndex, PeerMap<tecdsa::Scalar>> round2_shares;
  for (PartyIndex party : participants) {
    PeerMap<KeygenRound1Msg> peer_round1;
    for (PartyIndex peer : participants) {
      if (peer != party) {
        peer_round1.emplace(peer, round1.at(peer));
      }
    }
    const auto round2 = parties.at(party).MakeRound2(peer_round1);
    round2_broadcasts.emplace(party, round2.broadcast);
    round2_shares.emplace(party, round2.shares_for_peers);
  }

  std::unordered_map<PartyIndex, tecdsa::proto::KeygenRound3Msg> round3;
  for (PartyIndex party : participants) {
    PeerMap<KeygenRound2Broadcast> peer_round2;
    PeerMap<tecdsa::Scalar> shares_for_self;
    for (PartyIndex peer : participants) {
      if (peer == party) {
        continue;
      }
      peer_round2.emplace(peer, round2_broadcasts.at(peer));
      shares_for_self.emplace(peer, round2_shares.at(peer).at(party));
    }
    round3.emplace(party, parties.at(party).MakeRound3(peer_round2,
                                                        shares_for_self));
  }

  std::unordered_map<PartyIndex, KeygenOutput> outputs;
  for (PartyIndex party : participants) {
    PeerMap<tecdsa::proto::KeygenRound3Msg> peer_round3;
    for (PartyIndex peer : participants) {
      if (peer != party) {
        peer_round3.emplace(peer, round3.at(peer));
      }
    }
    outputs.emplace(party, parties.at(party).Finalize(peer_round3));
  }

  const auto& baseline = outputs.at(1).public_keygen_data;
  for (PartyIndex party : participants) {
    const auto& current = outputs.at(party);
    Expect(current.local_key_share.x_i.value() != 0,
           "local x_i share must be non-zero");
    Expect(current.local_key_share.paillier != nullptr,
           "local Paillier provider must be present");
    Expect(current.public_keygen_data.y == baseline.y,
           "all parties must agree on y");
    Expect(current.public_keygen_data.all_X_i.size() == participants.size(),
           "all_X_i must contain all participants");
    Expect(current.public_keygen_data.all_paillier_public.size() ==
               participants.size(),
           "all_paillier_public must contain all participants");
    Expect(current.public_keygen_data.all_aux_rsa_params.size() ==
               participants.size(),
           "all_aux_rsa_params must contain all participants");
    Expect(current.public_keygen_data.all_square_free_proofs.size() ==
               participants.size(),
           "all_square_free_proofs must contain all participants");
    Expect(current.public_keygen_data.all_aux_param_proofs.size() ==
               participants.size(),
           "all_aux_param_proofs must contain all participants");
    Expect(current.public_keygen_data.all_X_i.at(party) ==
               current.local_key_share.X_i,
           "self X_i must match the local key share");
  }
}

}  // namespace

int main() {
  try {
    RunThreePartyKeygenSmoke();
  } catch (const std::exception& ex) {
    std::cerr << ex.what() << '\n';
    return 1;
  }

  std::cout << "proto_keygen_smoke_tests passed" << '\n';
  return 0;
}
