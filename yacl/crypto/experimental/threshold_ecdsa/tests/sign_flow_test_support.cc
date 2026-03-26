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

#include <stdexcept>
#include <string>
#include <utility>

#include "sign_flow_test_shared.h"

namespace tecdsa::sign_flow_test {
namespace {

template <typename T>
PeerMap<T> BuildPeerMapFor(const std::vector<PartyIndex>& signers,
                           PartyIndex self_id, const PeerMap<T>& all_messages) {
  PeerMap<T> peer_map;
  for (PartyIndex peer : signers) {
    if (peer == self_id) {
      continue;
    }
    peer_map.emplace(peer, all_messages.at(peer));
  }
  return peer_map;
}

std::unordered_map<PartyIndex, std::vector<SignRound2Request>>
GroupRound2RequestsByRecipient(const std::vector<SignRound2Request>& requests) {
  std::unordered_map<PartyIndex, std::vector<SignRound2Request>> grouped;
  for (const SignRound2Request& request : requests) {
    grouped[request.to].push_back(request);
  }
  return grouped;
}

std::unordered_map<PartyIndex, std::vector<SignRound2Response>>
GroupRound2ResponsesByRecipient(
    const std::vector<SignRound2Response>& responses) {
  std::unordered_map<PartyIndex, std::vector<SignRound2Response>> grouped;
  for (const SignRound2Response& response : responses) {
    grouped[response.to].push_back(response);
  }
  return grouped;
}

}  // namespace

void Expect(bool condition, const std::string& message) {
  if (!condition) {
    throw std::runtime_error("Test failed: " + message);
  }
}

void ExpectThrow(const std::function<void()>& fn, const std::string& message) {
  bool threw = false;
  try {
    fn();
  } catch (const std::exception&) {
    threw = true;
  }
  if (!threw) {
    throw std::runtime_error("Test failed: " + message);
  }
}

std::vector<PartyIndex> BuildParticipants(uint32_t n) {
  std::vector<PartyIndex> out;
  out.reserve(n);
  for (PartyIndex id = 1; id <= n; ++id) {
    out.push_back(id);
  }
  return out;
}

size_t FindPartyIndexOrThrow(const std::vector<PartyIndex>& parties,
                             PartyIndex party_id) {
  for (size_t i = 0; i < parties.size(); ++i) {
    if (parties[i] == party_id) {
      return i;
    }
  }
  throw std::runtime_error("party not found in test vector");
}

KeygenOutputs RunKeygenAndCollectResults(uint32_t n, uint32_t t,
                                         const Bytes& session_id) {
  using tecdsa::proto::KeygenConfig;
  using tecdsa::proto::KeygenParty;
  using tecdsa::proto::KeygenRound1Msg;
  using tecdsa::proto::KeygenRound2Broadcast;

  const std::vector<PartyIndex> participants = BuildParticipants(n);
  std::unordered_map<PartyIndex, KeygenParty> parties;
  for (PartyIndex party : participants) {
    KeygenConfig cfg;
    cfg.session_id = session_id;
    cfg.self_id = party;
    cfg.participants = participants;
    cfg.threshold = t;
    parties.emplace(party, KeygenParty(std::move(cfg)));
  }

  std::unordered_map<PartyIndex, KeygenRound1Msg> round1;
  for (PartyIndex party : participants) {
    round1.emplace(party, parties.at(party).MakeRound1());
  }

  std::unordered_map<PartyIndex, KeygenRound2Broadcast> round2_broadcasts;
  std::unordered_map<PartyIndex, PeerMap<Scalar>> round2_shares;
  for (PartyIndex party : participants) {
    PeerMap<KeygenRound1Msg> peer_round1 =
        BuildPeerMapFor(participants, party, round1);
    const auto round2 = parties.at(party).MakeRound2(peer_round1);
    round2_broadcasts.emplace(party, round2.broadcast);
    round2_shares.emplace(party, round2.shares_for_peers);
  }

  std::unordered_map<PartyIndex, tecdsa::proto::KeygenRound3Msg> round3;
  for (PartyIndex party : participants) {
    PeerMap<KeygenRound2Broadcast> peer_round2 =
        BuildPeerMapFor(participants, party, round2_broadcasts);
    PeerMap<Scalar> shares_for_self;
    for (PartyIndex peer : participants) {
      if (peer != party) {
        shares_for_self.emplace(peer, round2_shares.at(peer).at(party));
      }
    }
    round3.emplace(party,
                   parties.at(party).MakeRound3(peer_round2, shares_for_self));
  }

  KeygenOutputs outputs;
  for (PartyIndex party : participants) {
    const auto peer_round3 = BuildPeerMapFor(participants, party, round3);
    outputs.emplace(party, parties.at(party).Finalize(peer_round3));
  }
  return outputs;
}

SignFixture BuildSignFixture(const std::vector<PartyIndex>& signers) {
  SignFixture fixture;
  fixture.signers = signers;
  fixture.msg32.assign(32, static_cast<uint8_t>(0x5A));
  return fixture;
}

tecdsa::StrictProofVerifierContext BuildKeygenProofContext(
    const Bytes& keygen_session_id, PartyIndex prover_id) {
  tecdsa::StrictProofVerifierContext context;
  context.session_id = keygen_session_id;
  context.prover_id = prover_id;
  return context;
}

std::vector<SignConfig> BuildSignConfigs(const SignFixture& fixture,
                                         const KeygenOutputs& keygen_results,
                                         const Bytes& sign_session_id,
                                         const Bytes& keygen_session_id) {
  std::vector<SignConfig> configs;
  configs.reserve(fixture.signers.size());
  for (PartyIndex signer : fixture.signers) {
    const auto result_it = keygen_results.find(signer);
    if (result_it == keygen_results.end()) {
      throw std::runtime_error("missing keygen result for signer");
    }

    SignConfig cfg;
    cfg.session_id = sign_session_id;
    cfg.keygen_session_id = keygen_session_id;
    cfg.self_id = signer;
    cfg.participants = fixture.signers;
    cfg.local_key_share = result_it->second.local_key_share;
    cfg.public_keygen_data = result_it->second.public_keygen_data;
    cfg.msg32 = fixture.msg32;
    configs.push_back(std::move(cfg));
  }
  return configs;
}

SignPartyMap BuildSignParties(const SignFixture& fixture,
                              const KeygenOutputs& keygen_results,
                              const Bytes& sign_session_id,
                              const Bytes& keygen_session_id) {
  std::vector<SignConfig> configs = BuildSignConfigs(
      fixture, keygen_results, sign_session_id, keygen_session_id);
  SignPartyMap parties;
  for (SignConfig& cfg : configs) {
    parties.emplace(cfg.self_id, SignParty(std::move(cfg)));
  }
  return parties;
}

PeerMap<SignRound1Msg> CollectRound1Messages(
    SignPartyMap* parties, const std::vector<PartyIndex>& signers) {
  PeerMap<SignRound1Msg> round1;
  for (PartyIndex signer : signers) {
    round1.emplace(signer, parties->at(signer).MakeRound1());
  }
  return round1;
}

std::vector<SignRound2Request> CollectRound2Requests(
    SignPartyMap* parties, const std::vector<PartyIndex>& signers,
    const PeerMap<SignRound1Msg>& round1) {
  std::vector<SignRound2Request> out;
  for (PartyIndex signer : signers) {
    const auto peer_round1 = BuildPeerMapFor(signers, signer, round1);
    const auto requests = parties->at(signer).MakeRound2Requests(peer_round1);
    out.insert(out.end(), requests.begin(), requests.end());
  }
  return out;
}

std::vector<SignRound2Response> CollectRound2Responses(
    SignPartyMap* parties, const std::vector<PartyIndex>& signers,
    const std::vector<SignRound2Request>& round2_requests) {
  const auto grouped = GroupRound2RequestsByRecipient(round2_requests);
  std::vector<SignRound2Response> out;
  for (PartyIndex signer : signers) {
    const auto it = grouped.find(signer);
    if (it == grouped.end()) {
      throw std::runtime_error("missing round2 requests for signer");
    }
    const auto responses = parties->at(signer).MakeRound2Responses(it->second);
    out.insert(out.end(), responses.begin(), responses.end());
  }
  return out;
}

PeerMap<SignRound3Msg> CollectRound3Messages(
    SignPartyMap* parties, const std::vector<PartyIndex>& signers,
    const std::vector<SignRound2Response>& round2_responses) {
  const auto grouped = GroupRound2ResponsesByRecipient(round2_responses);
  PeerMap<SignRound3Msg> round3;
  for (PartyIndex signer : signers) {
    const auto it = grouped.find(signer);
    if (it == grouped.end()) {
      throw std::runtime_error("missing round2 responses for signer");
    }
    round3.emplace(signer, parties->at(signer).MakeRound3(it->second));
  }
  return round3;
}

PeerMap<SignRound4Msg> CollectRound4Messages(
    SignPartyMap* parties, const std::vector<PartyIndex>& signers,
    const PeerMap<SignRound3Msg>& round3) {
  PeerMap<SignRound4Msg> round4;
  for (PartyIndex signer : signers) {
    round4.emplace(signer, parties->at(signer).MakeRound4(
                               BuildPeerMapFor(signers, signer, round3)));
  }
  return round4;
}

PeerMap<SignRound5AMsg> CollectRound5AMessages(
    SignPartyMap* parties, const std::vector<PartyIndex>& signers,
    const PeerMap<SignRound4Msg>& round4) {
  PeerMap<SignRound5AMsg> round5a;
  for (PartyIndex signer : signers) {
    round5a.emplace(signer, parties->at(signer).MakeRound5A(
                                BuildPeerMapFor(signers, signer, round4)));
  }
  return round5a;
}

PeerMap<SignRound5BMsg> CollectRound5BMessages(
    SignPartyMap* parties, const std::vector<PartyIndex>& signers,
    const PeerMap<SignRound5AMsg>& round5a) {
  PeerMap<SignRound5BMsg> round5b;
  for (PartyIndex signer : signers) {
    round5b.emplace(signer, parties->at(signer).MakeRound5B(
                                BuildPeerMapFor(signers, signer, round5a)));
  }
  return round5b;
}

PeerMap<SignRound5CMsg> CollectRound5CMessages(
    SignPartyMap* parties, const std::vector<PartyIndex>& signers,
    const PeerMap<SignRound5BMsg>& round5b) {
  PeerMap<SignRound5CMsg> round5c;
  for (PartyIndex signer : signers) {
    round5c.emplace(signer, parties->at(signer).MakeRound5C(
                                BuildPeerMapFor(signers, signer, round5b)));
  }
  return round5c;
}

PeerMap<SignRound5DMsg> CollectRound5DMessages(
    SignPartyMap* parties, const std::vector<PartyIndex>& signers,
    const PeerMap<SignRound5CMsg>& round5c) {
  PeerMap<SignRound5DMsg> round5d;
  for (PartyIndex signer : signers) {
    round5d.emplace(signer, parties->at(signer).MakeRound5D(
                                BuildPeerMapFor(signers, signer, round5c)));
  }
  return round5d;
}

PeerMap<Scalar> CollectRound5EReveals(SignPartyMap* parties,
                                      const std::vector<PartyIndex>& signers,
                                      const PeerMap<SignRound5DMsg>& round5d) {
  PeerMap<Scalar> round5e;
  for (PartyIndex signer : signers) {
    round5e.emplace(signer, parties->at(signer).RevealRound5E(
                                BuildPeerMapFor(signers, signer, round5d)));
  }
  return round5e;
}

PeerMap<Signature> FinalizeSignatures(SignPartyMap* parties,
                                      const std::vector<PartyIndex>& signers,
                                      const PeerMap<Scalar>& round5e) {
  PeerMap<Signature> signatures;
  for (PartyIndex signer : signers) {
    signatures.emplace(signer, parties->at(signer).Finalize(
                                   BuildPeerMapFor(signers, signer, round5e)));
  }
  return signatures;
}

}  // namespace tecdsa::sign_flow_test
