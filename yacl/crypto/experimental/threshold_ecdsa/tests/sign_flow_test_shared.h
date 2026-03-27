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

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "yacl/crypto/experimental/threshold_ecdsa/protocol/keygen.h"
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/sign.h"

namespace tecdsa::sign_flow_test {

using ::tecdsa::Bytes;
using ::tecdsa::PartyIndex;
using ::tecdsa::Scalar;
using ::tecdsa::proto::KeygenOutput;
using ::tecdsa::proto::KeygenParty;
using ::tecdsa::proto::KeygenRound1Msg;
using ::tecdsa::proto::KeygenRound2Broadcast;
using ::tecdsa::proto::KeygenRound3Msg;
using ::tecdsa::proto::PeerMap;
using ::tecdsa::proto::Signature;
using ::tecdsa::proto::SignConfig;
using ::tecdsa::proto::SignParty;
using ::tecdsa::proto::SignRound1Msg;
using ::tecdsa::proto::SignRound2Request;
using ::tecdsa::proto::SignRound2Response;
using ::tecdsa::proto::SignRound3Msg;
using ::tecdsa::proto::SignRound4Msg;
using ::tecdsa::proto::SignRound5AMsg;
using ::tecdsa::proto::SignRound5BMsg;
using ::tecdsa::proto::SignRound5CMsg;
using ::tecdsa::proto::SignRound5DMsg;

using KeygenOutputs = std::unordered_map<PartyIndex, KeygenOutput>;
using KeygenPartyMap = std::unordered_map<PartyIndex, KeygenParty>;
using KeygenRound2Shares = std::unordered_map<PartyIndex, PeerMap<Scalar>>;
using SignPartyMap = std::unordered_map<PartyIndex, SignParty>;

template <typename T>
PeerMap<T> BuildPeerMapFor(const std::vector<PartyIndex>& parties,
                           PartyIndex self_id,
                           const std::unordered_map<PartyIndex, T>& all_msgs) {
  PeerMap<T> out;
  for (PartyIndex peer : parties) {
    if (peer != self_id) {
      out.emplace(peer, all_msgs.at(peer));
    }
  }
  return out;
}

struct SignFixture {
  std::vector<PartyIndex> signers;
  Bytes msg32;
};

void Expect(bool condition, const std::string& message);
void ExpectThrow(const std::function<void()>& fn, const std::string& message);

std::vector<PartyIndex> BuildParticipants(uint32_t n);
size_t FindPartyIndexOrThrow(const std::vector<PartyIndex>& parties,
                             PartyIndex party_id);

KeygenPartyMap BuildParties(uint32_t n, uint32_t t, const Bytes& session_id);
PeerMap<KeygenRound1Msg> CollectRound1(
    KeygenPartyMap* parties, const std::vector<PartyIndex>& participants);
void CollectRound2(KeygenPartyMap* parties,
                   const std::vector<PartyIndex>& participants,
                   const PeerMap<KeygenRound1Msg>& round1,
                   PeerMap<KeygenRound2Broadcast>* broadcasts,
                   KeygenRound2Shares* shares);
PeerMap<KeygenRound3Msg> CollectRound3(
    KeygenPartyMap* parties, const std::vector<PartyIndex>& participants,
    const PeerMap<KeygenRound2Broadcast>& broadcasts,
    const KeygenRound2Shares& shares);
KeygenOutputs FinalizeOutputs(KeygenPartyMap* parties,
                              const std::vector<PartyIndex>& participants,
                              const PeerMap<KeygenRound3Msg>& round3);
KeygenOutputs RunKeygenAndCollectResults(uint32_t n, uint32_t t,
                                         const Bytes& session_id);

SignFixture BuildSignFixture(const std::vector<PartyIndex>& signers);
tecdsa::StrictProofVerifierContext BuildKeygenProofContext(
    const Bytes& keygen_session_id, PartyIndex prover_id);

std::vector<SignConfig> BuildSignConfigs(const SignFixture& fixture,
                                         const KeygenOutputs& keygen_results,
                                         const Bytes& sign_session_id,
                                         const Bytes& keygen_session_id);
SignPartyMap BuildSignParties(const SignFixture& fixture,
                              const KeygenOutputs& keygen_results,
                              const Bytes& sign_session_id,
                              const Bytes& keygen_session_id);

PeerMap<SignRound1Msg> CollectRound1Messages(
    SignPartyMap* parties, const std::vector<PartyIndex>& signers);
std::vector<SignRound2Request> CollectRound2Requests(
    SignPartyMap* parties, const std::vector<PartyIndex>& signers,
    const PeerMap<SignRound1Msg>& round1);
std::vector<SignRound2Response> CollectRound2Responses(
    SignPartyMap* parties, const std::vector<PartyIndex>& signers,
    const std::vector<SignRound2Request>& round2_requests);
PeerMap<SignRound3Msg> CollectRound3Messages(
    SignPartyMap* parties, const std::vector<PartyIndex>& signers,
    const std::vector<SignRound2Response>& round2_responses);
PeerMap<SignRound4Msg> CollectRound4Messages(
    SignPartyMap* parties, const std::vector<PartyIndex>& signers,
    const PeerMap<SignRound3Msg>& round3);
PeerMap<SignRound5AMsg> CollectRound5AMessages(
    SignPartyMap* parties, const std::vector<PartyIndex>& signers,
    const PeerMap<SignRound4Msg>& round4);
PeerMap<SignRound5BMsg> CollectRound5BMessages(
    SignPartyMap* parties, const std::vector<PartyIndex>& signers,
    const PeerMap<SignRound5AMsg>& round5a);
PeerMap<SignRound5CMsg> CollectRound5CMessages(
    SignPartyMap* parties, const std::vector<PartyIndex>& signers,
    const PeerMap<SignRound5BMsg>& round5b);
PeerMap<SignRound5DMsg> CollectRound5DMessages(
    SignPartyMap* parties, const std::vector<PartyIndex>& signers,
    const PeerMap<SignRound5CMsg>& round5c);
PeerMap<Scalar> CollectRound5EReveals(SignPartyMap* parties,
                                      const std::vector<PartyIndex>& signers,
                                      const PeerMap<SignRound5DMsg>& round5d);
PeerMap<Signature> FinalizeSignatures(SignPartyMap* parties,
                                      const std::vector<PartyIndex>& signers,
                                      const PeerMap<Scalar>& round5e);

void TestStage4SignConstructorRejectsSmallPaillierModulus();
void TestStage6SignConstructorRejectsMissingKeygenProofArtifacts();
void TestStage6SignConstructorRejectsInvalidKeygenProofArtifacts();
void TestStage6MalformedPhase2InitProofPayloadAbortsResponder();
void TestStage6MalformedPhase2ResponseProofPayloadAbortsInitiator();
void TestStage4Phase2InitUsesResponderOwnedAuxParams();
void TestStage4Phase2ResponseUsesInitiatorOwnedAuxParams();
void TestM4SignEndToEndProducesVerifiableSignature();
void TestM4Phase5DFailurePreventsPhase5EReveal();
void TestM5Phase2InstanceIdMismatchAborts();
void TestM7TamperedPhase2A1ProofAbortsResponder();
void TestM7TamperedPhase2A3ProofAbortsInitiator();
void TestM7TamperedPhase2A2ProofAbortsInitiator();
void TestM6TamperedPhase4GammaSchnorrAbortsReceiver();
void TestM6TamperedPhase5BASchnorrAbortsReceiver();
void TestM6TamperedPhase5BVRelationAbortsReceiver();
void TestM9TamperedPhase4GammaPointAbortsReceiver();
void TestM9TamperedPhase5ACommitmentAbortsReceiver();
void TestM9TamperedPhase3DeltaShareAbortsAndNoResult();
void TestM9TamperedPhase5BVPointAbortsReceiver();

}  // namespace tecdsa::sign_flow_test
