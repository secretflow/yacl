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

#include "yacl/crypto/experimental/threshold_ecdsa/crypto/ecdsa_verify.h"
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/keygen.h"
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/sign.h"

namespace {

void Expect(bool condition, const std::string& message) {
  if (!condition) {
    throw std::runtime_error("Test failed: " + message);
  }
}

std::unordered_map<tecdsa::PartyIndex, tecdsa::proto::KeygenOutput>
RunThreePartyKeygen(const tecdsa::Bytes& session_id) {
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
    cfg.session_id = session_id;
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
    round3.emplace(party,
                   parties.at(party).MakeRound3(peer_round2, shares_for_self));
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
  return outputs;
}

void RunTwoOfThreeSignSmoke() {
  using tecdsa::PartyIndex;
  using tecdsa::proto::PeerMap;
  using tecdsa::proto::Signature;
  using tecdsa::proto::SignConfig;
  using tecdsa::proto::SignParty;
  using tecdsa::proto::SignRound1Msg;
  using tecdsa::proto::SignRound2Request;
  using tecdsa::proto::SignRound2Response;
  using tecdsa::proto::SignRound3Msg;
  using tecdsa::proto::SignRound4Msg;
  using tecdsa::proto::SignRound5AMsg;
  using tecdsa::proto::SignRound5BMsg;
  using tecdsa::proto::SignRound5CMsg;
  using tecdsa::proto::SignRound5DMsg;

  const auto keygen_outputs =
      RunThreePartyKeygen(tecdsa::Bytes{0x11, 0x22, 0x33});
  const std::vector<PartyIndex> signers = {1, 2};
  const tecdsa::Bytes msg32(32, 0x5A);

  std::unordered_map<PartyIndex, SignParty> parties;
  for (PartyIndex signer : signers) {
    SignConfig cfg;
    cfg.session_id = {0x44, 0x55, 0x66};
    cfg.keygen_session_id = {0x11, 0x22, 0x33};
    cfg.self_id = signer;
    cfg.participants = signers;
    cfg.local_key_share = keygen_outputs.at(signer).local_key_share;
    cfg.public_keygen_data = keygen_outputs.at(signer).public_keygen_data;
    cfg.msg32 = msg32;
    parties.emplace(signer, SignParty(std::move(cfg)));
  }

  std::unordered_map<PartyIndex, SignRound1Msg> round1;
  for (PartyIndex signer : signers) {
    round1.emplace(signer, parties.at(signer).MakeRound1());
  }

  std::vector<SignRound2Request> all_round2_requests;
  for (PartyIndex signer : signers) {
    PeerMap<SignRound1Msg> peer_round1;
    for (PartyIndex peer : signers) {
      if (peer != signer) {
        peer_round1.emplace(peer, round1.at(peer));
      }
    }
    const auto requests = parties.at(signer).MakeRound2Requests(peer_round1);
    all_round2_requests.insert(all_round2_requests.end(), requests.begin(),
                               requests.end());
  }

  std::unordered_map<PartyIndex, std::vector<SignRound2Request>>
      requests_for_self;
  for (const SignRound2Request& request : all_round2_requests) {
    requests_for_self[request.to].push_back(request);
  }

  std::vector<SignRound2Response> all_round2_responses;
  for (PartyIndex signer : signers) {
    const auto responses =
        parties.at(signer).MakeRound2Responses(requests_for_self.at(signer));
    all_round2_responses.insert(all_round2_responses.end(), responses.begin(),
                                responses.end());
  }

  std::unordered_map<PartyIndex, std::vector<SignRound2Response>>
      responses_for_self;
  for (const SignRound2Response& response : all_round2_responses) {
    responses_for_self[response.to].push_back(response);
  }

  std::unordered_map<PartyIndex, SignRound3Msg> round3;
  for (PartyIndex signer : signers) {
    round3.emplace(
        signer, parties.at(signer).MakeRound3(responses_for_self.at(signer)));
  }

  std::unordered_map<PartyIndex, SignRound4Msg> round4;
  for (PartyIndex signer : signers) {
    PeerMap<SignRound3Msg> peer_round3;
    for (PartyIndex peer : signers) {
      if (peer != signer) {
        peer_round3.emplace(peer, round3.at(peer));
      }
    }
    round4.emplace(signer, parties.at(signer).MakeRound4(peer_round3));
  }

  std::unordered_map<PartyIndex, SignRound5AMsg> round5a;
  for (PartyIndex signer : signers) {
    PeerMap<SignRound4Msg> peer_round4;
    for (PartyIndex peer : signers) {
      if (peer != signer) {
        peer_round4.emplace(peer, round4.at(peer));
      }
    }
    round5a.emplace(signer, parties.at(signer).MakeRound5A(peer_round4));
  }

  std::unordered_map<PartyIndex, SignRound5BMsg> round5b;
  for (PartyIndex signer : signers) {
    PeerMap<SignRound5AMsg> peer_round5a;
    for (PartyIndex peer : signers) {
      if (peer != signer) {
        peer_round5a.emplace(peer, round5a.at(peer));
      }
    }
    round5b.emplace(signer, parties.at(signer).MakeRound5B(peer_round5a));
  }

  std::unordered_map<PartyIndex, SignRound5CMsg> round5c;
  for (PartyIndex signer : signers) {
    PeerMap<SignRound5BMsg> peer_round5b;
    for (PartyIndex peer : signers) {
      if (peer != signer) {
        peer_round5b.emplace(peer, round5b.at(peer));
      }
    }
    round5c.emplace(signer, parties.at(signer).MakeRound5C(peer_round5b));
  }

  std::unordered_map<PartyIndex, SignRound5DMsg> round5d;
  for (PartyIndex signer : signers) {
    PeerMap<SignRound5CMsg> peer_round5c;
    for (PartyIndex peer : signers) {
      if (peer != signer) {
        peer_round5c.emplace(peer, round5c.at(peer));
      }
    }
    round5d.emplace(signer, parties.at(signer).MakeRound5D(peer_round5c));
  }

  std::unordered_map<PartyIndex, tecdsa::Scalar> round5e;
  for (PartyIndex signer : signers) {
    PeerMap<SignRound5DMsg> peer_round5d;
    for (PartyIndex peer : signers) {
      if (peer != signer) {
        peer_round5d.emplace(peer, round5d.at(peer));
      }
    }
    round5e.emplace(signer, parties.at(signer).RevealRound5E(peer_round5d));
  }

  std::unordered_map<PartyIndex, Signature> signatures;
  for (PartyIndex signer : signers) {
    PeerMap<tecdsa::Scalar> peer_round5e;
    for (PartyIndex peer : signers) {
      if (peer != signer) {
        peer_round5e.emplace(peer, round5e.at(peer));
      }
    }
    signatures.emplace(signer, parties.at(signer).Finalize(peer_round5e));
  }

  const Signature& baseline = signatures.at(signers.front());
  Expect(baseline.r.value() != 0, "signature r must be non-zero");
  Expect(baseline.s.value() != 0, "signature s must be non-zero");
  Expect(tecdsa::VerifyEcdsaSignatureMath(
             keygen_outputs.at(signers.front()).public_keygen_data.y, msg32,
             baseline.r, baseline.s),
         "smoke signature must verify");

  for (PartyIndex signer : signers) {
    const Signature& signature = signatures.at(signer);
    Expect(signature.r == baseline.r, "all signers must agree on r");
    Expect(signature.s == baseline.s, "all signers must agree on s");
    Expect(signature.R == baseline.R, "all signers must agree on R");
  }
}

}  // namespace

int main() {
  try {
    RunTwoOfThreeSignSmoke();
  } catch (const std::exception& ex) {
    std::cerr << ex.what() << '\n';
    return 1;
  }

  std::cout << "proto_sign_smoke_tests passed" << '\n';
  return 0;
}
