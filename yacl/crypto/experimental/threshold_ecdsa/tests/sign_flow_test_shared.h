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
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include "yacl/crypto/experimental/threshold_ecdsa/net/envelope.h"
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/keygen_session.h"
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/sign_session.h"

namespace tecdsa::sign_flow_test {

using ::tecdsa::Bytes;
using ::tecdsa::Envelope;
using ::tecdsa::KeygenPhase;
using ::tecdsa::KeygenResult;
using ::tecdsa::KeygenSession;
using ::tecdsa::KeygenSessionConfig;
using ::tecdsa::PaillierPublicKey;
using ::tecdsa::PartyIndex;
using ::tecdsa::Scalar;
using ::tecdsa::SessionStatus;
using ::tecdsa::SignPhase;
using ::tecdsa::SignPhase5Stage;
using ::tecdsa::SignSession;
using ::tecdsa::SignSessionConfig;

struct SignFixture {
  std::vector<PartyIndex> signers;
  Bytes msg32;
  std::unordered_map<PartyIndex, Scalar> fixed_k;
  std::unordered_map<PartyIndex, Scalar> fixed_gamma;
};

void Expect(bool condition, const std::string& message);
void ExpectThrow(const std::function<void()>& fn, const std::string& message);

std::vector<PartyIndex> BuildParticipants(uint32_t n);
size_t FindPartyIndexOrThrow(const std::vector<PartyIndex>& parties,
                             PartyIndex party_id);

std::vector<std::unique_ptr<KeygenSession>> BuildKeygenSessions(
    uint32_t n, uint32_t t, const Bytes& session_id);
bool DeliverKeygenEnvelope(
    const Envelope& envelope,
    std::vector<std::unique_ptr<KeygenSession>>* sessions);
void DeliverKeygenEnvelopesOrThrow(
    const std::vector<Envelope>& envelopes,
    std::vector<std::unique_ptr<KeygenSession>>* sessions);
std::unordered_map<PartyIndex, KeygenResult> RunKeygenAndCollectResults(
    uint32_t n, uint32_t t, const Bytes& session_id);

SignFixture BuildSignFixture(const std::vector<PartyIndex>& signers);
tecdsa::StrictProofVerifierContext BuildKeygenProofContext(
    const Bytes& keygen_session_id, PartyIndex prover_id);

std::vector<SignSessionConfig> BuildSignSessionConfigs(
    const SignFixture& fixture,
    const std::unordered_map<PartyIndex, KeygenResult>& keygen_results,
    const Bytes& sign_session_id);

std::vector<std::unique_ptr<SignSession>> BuildSignSessions(
    const SignFixture& fixture,
    const std::unordered_map<PartyIndex, KeygenResult>& keygen_results,
    const Bytes& sign_session_id);

bool DeliverSignEnvelope(const Envelope& envelope,
                         const std::vector<PartyIndex>& signers,
                         std::vector<std::unique_ptr<SignSession>>* sessions);
void DeliverSignEnvelopesOrThrow(
    const std::vector<Envelope>& envelopes,
    const std::vector<PartyIndex>& signers,
    std::vector<std::unique_ptr<SignSession>>* sessions);

std::vector<Envelope> CollectPhase1Messages(
    std::vector<std::unique_ptr<SignSession>>* sessions);
std::vector<Envelope> CollectPhase2Messages(
    std::vector<std::unique_ptr<SignSession>>* sessions);
std::vector<Envelope> CollectPhase3Messages(
    std::vector<std::unique_ptr<SignSession>>* sessions);
std::vector<Envelope> CollectPhase4Messages(
    std::vector<std::unique_ptr<SignSession>>* sessions);
std::vector<Envelope> CollectPhase5AMessages(
    std::vector<std::unique_ptr<SignSession>>* sessions);
std::vector<Envelope> CollectPhase5BMessages(
    std::vector<std::unique_ptr<SignSession>>* sessions);
std::vector<Envelope> CollectPhase5CMessages(
    std::vector<std::unique_ptr<SignSession>>* sessions);
std::vector<Envelope> CollectPhase5DMessages(
    std::vector<std::unique_ptr<SignSession>>* sessions);
std::vector<Envelope> CollectPhase5EMessages(
    std::vector<std::unique_ptr<SignSession>>* sessions);

void EnsureAllSessionsInPhase(
    const std::vector<std::unique_ptr<SignSession>>& sessions, SignPhase phase,
    SignPhase5Stage phase5_stage = SignPhase5Stage::kPhase5A);

void RunToPhase4(std::vector<std::unique_ptr<SignSession>>* sessions,
                 const std::vector<PartyIndex>& signers);
void RunToPhase5A(std::vector<std::unique_ptr<SignSession>>* sessions,
                  const std::vector<PartyIndex>& signers);
void RunToPhase5B(std::vector<std::unique_ptr<SignSession>>* sessions,
                  const std::vector<PartyIndex>& signers);
void RunToPhase5D(std::vector<std::unique_ptr<SignSession>>* sessions,
                  const std::vector<PartyIndex>& signers);

uint32_t ReadU32Be(const Bytes& input, size_t offset);
bool TamperPhase5BSchnorrProof(Envelope* envelope);
bool ReplacePhase4GammaPoint(Envelope* envelope,
                             std::span<const uint8_t> replacement_point);
bool ReplacePhase5BVPoint(Envelope* envelope,
                          std::span<const uint8_t> replacement_point);

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
