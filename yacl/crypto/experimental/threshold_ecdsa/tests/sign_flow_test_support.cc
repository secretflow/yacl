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

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include "sign_flow_test_shared.h"

namespace tecdsa::sign_flow_test {

void Expect(bool condition, const std::string& message) {
  if (!condition) {
    throw std::runtime_error("Test failed: " + message);
  }
}

void ExpectThrow(const std::function<void()>& fn, const std::string& message) {
  try {
    fn();
  } catch (const std::exception&) {
    return;
  }
  throw std::runtime_error("Expected exception: " + message);
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
  throw std::runtime_error("party id not found in parties vector");
}

std::vector<std::unique_ptr<KeygenSession>> BuildKeygenSessions(
    uint32_t n, uint32_t t, const Bytes& session_id) {
  const std::vector<PartyIndex> participants = BuildParticipants(n);

  std::vector<std::unique_ptr<KeygenSession>> sessions;
  sessions.reserve(n);
  for (PartyIndex self_id : participants) {
    KeygenSessionConfig cfg;
    cfg.session_id = session_id;
    cfg.self_id = self_id;
    cfg.participants = participants;
    cfg.threshold = t;
    cfg.timeout = std::chrono::seconds(10);
    cfg.strict_mode = true;
    cfg.require_aux_param_proof = true;
    sessions.push_back(std::make_unique<KeygenSession>(std::move(cfg)));
  }
  return sessions;
}

bool DeliverKeygenEnvelope(
    const Envelope& envelope,
    std::vector<std::unique_ptr<KeygenSession>>* sessions) {
  bool ok = true;

  if (envelope.to == tecdsa::kBroadcastPartyId) {
    for (size_t idx = 0; idx < sessions->size(); ++idx) {
      const PartyIndex receiver = static_cast<PartyIndex>(idx + 1);
      if (receiver == envelope.from) {
        continue;
      }
      if (!(*sessions)[idx]->HandleEnvelope(envelope)) {
        ok = false;
      }
    }
    return ok;
  }

  if (envelope.to == 0 || envelope.to > sessions->size()) {
    throw std::runtime_error("Envelope recipient is out of range");
  }

  if (!(*sessions)[envelope.to - 1]->HandleEnvelope(envelope)) {
    ok = false;
  }
  return ok;
}

void DeliverKeygenEnvelopesOrThrow(
    const std::vector<Envelope>& envelopes,
    std::vector<std::unique_ptr<KeygenSession>>* sessions) {
  for (const Envelope& envelope : envelopes) {
    if (!DeliverKeygenEnvelope(envelope, sessions)) {
      throw std::runtime_error("Unexpected keygen envelope delivery failure");
    }
  }
}

std::unordered_map<PartyIndex, KeygenResult> RunKeygenAndCollectResults(
    uint32_t n, uint32_t t, const Bytes& session_id) {
  auto sessions = BuildKeygenSessions(n, t, session_id);

  std::vector<Envelope> phase1;
  phase1.reserve(n);
  for (auto& session : sessions) {
    phase1.push_back(session->BuildPhase1CommitEnvelope());
  }
  DeliverKeygenEnvelopesOrThrow(phase1, &sessions);

  std::vector<Envelope> phase2;
  for (auto& session : sessions) {
    const std::vector<Envelope> messages =
        session->BuildPhase2OpenAndShareEnvelopes();
    phase2.insert(phase2.end(), messages.begin(), messages.end());
  }
  DeliverKeygenEnvelopesOrThrow(phase2, &sessions);

  std::vector<Envelope> phase3;
  phase3.reserve(n);
  for (auto& session : sessions) {
    phase3.push_back(session->BuildPhase3XiProofEnvelope());
  }
  DeliverKeygenEnvelopesOrThrow(phase3, &sessions);

  std::unordered_map<PartyIndex, KeygenResult> results;
  for (size_t idx = 0; idx < sessions.size(); ++idx) {
    const PartyIndex party_id = static_cast<PartyIndex>(idx + 1);
    Expect(
        sessions[idx]->status() == SessionStatus::kCompleted,
        "Keygen session should complete for party " + std::to_string(party_id));
    results.emplace(party_id, sessions[idx]->result());
  }

  return results;
}

SignFixture BuildSignFixture(const std::vector<PartyIndex>& signers) {
  SignFixture fixture;
  fixture.signers = signers;
  fixture.msg32 = Bytes{
      0x4d, 0x34, 0x2d, 0x73, 0x69, 0x67, 0x6e, 0x2d, 0x74, 0x65, 0x73,
      0x74, 0x2d, 0x30, 0x30, 0x31, 0xaa, 0xbb, 0xcc, 0xdd, 0x10, 0x20,
      0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0,
  };
  for (PartyIndex party : signers) {
    const Scalar gamma_i = Scalar::FromUint64(20 + 2 * party);
    fixture.fixed_gamma.emplace(party, gamma_i);
  }

  for (PartyIndex party : signers) {
    const Scalar k_i = Scalar::FromUint64(10 + party);
    fixture.fixed_k.emplace(party, k_i);
  }

  return fixture;
}

tecdsa::StrictProofVerifierContext BuildKeygenProofContext(
    const Bytes& keygen_session_id, PartyIndex prover_id) {
  tecdsa::StrictProofVerifierContext context;
  context.session_id = keygen_session_id;
  context.prover_id = prover_id;
  return context;
}

std::vector<SignSessionConfig> BuildSignSessionConfigs(
    const SignFixture& fixture,
    const std::unordered_map<PartyIndex, KeygenResult>& keygen_results,
    const Bytes& sign_session_id) {
  std::vector<SignSessionConfig> configs;
  configs.reserve(fixture.signers.size());

  const auto baseline_it = keygen_results.find(fixture.signers.front());
  if (baseline_it == keygen_results.end()) {
    throw std::runtime_error("missing baseline keygen result");
  }

  std::unordered_map<PartyIndex, tecdsa::ECPoint> all_X_i_subset;
  all_X_i_subset.reserve(fixture.signers.size());
  for (PartyIndex party : fixture.signers) {
    const auto x_it = baseline_it->second.all_X_i.find(party);
    if (x_it == baseline_it->second.all_X_i.end()) {
      throw std::runtime_error("baseline keygen result missing X_i for signer");
    }
    all_X_i_subset.emplace(party, x_it->second);
  }

  std::unordered_map<PartyIndex, std::shared_ptr<tecdsa::PaillierProvider>>
      paillier_private;
  std::unordered_map<PartyIndex, tecdsa::PaillierPublicKey> paillier_public;
  std::unordered_map<PartyIndex, SignSessionConfig::AuxRsaParams> aux_params;
  std::unordered_map<PartyIndex, SignSessionConfig::SquareFreeProof>
      square_free_proofs;
  std::unordered_map<PartyIndex, SignSessionConfig::AuxRsaParamProof>
      aux_param_proofs;
  paillier_private.reserve(fixture.signers.size());
  paillier_public.reserve(fixture.signers.size());
  aux_params.reserve(fixture.signers.size());
  square_free_proofs.reserve(fixture.signers.size());
  aux_param_proofs.reserve(fixture.signers.size());
  for (PartyIndex party : fixture.signers) {
    const auto party_result_it = keygen_results.find(party);
    if (party_result_it == keygen_results.end()) {
      throw std::runtime_error("missing keygen result for signer Paillier key");
    }
    if (party_result_it->second.local_paillier == nullptr) {
      throw std::runtime_error(
          "missing local Paillier private key in keygen result");
    }
    const auto paillier_pub_it =
        party_result_it->second.all_paillier_public.find(party);
    if (paillier_pub_it == party_result_it->second.all_paillier_public.end()) {
      throw std::runtime_error(
          "missing self Paillier public key in keygen result");
    }

    paillier_public.emplace(party, paillier_pub_it->second);
    paillier_private.emplace(party, party_result_it->second.local_paillier);

    const auto aux_it = baseline_it->second.all_aux_rsa_params.find(party);
    if (aux_it == baseline_it->second.all_aux_rsa_params.end()) {
      throw std::runtime_error("missing signer aux params in keygen baseline");
    }
    aux_params.emplace(party, aux_it->second);

    const auto square_it =
        baseline_it->second.all_square_free_proofs.find(party);
    if (square_it == baseline_it->second.all_square_free_proofs.end()) {
      throw std::runtime_error(
          "missing signer square-free proof in keygen baseline");
    }
    square_free_proofs.emplace(party, square_it->second);

    const auto aux_pf_it = baseline_it->second.all_aux_param_proofs.find(party);
    if (aux_pf_it == baseline_it->second.all_aux_param_proofs.end()) {
      throw std::runtime_error(
          "missing signer aux param proof in keygen baseline");
    }
    aux_param_proofs.emplace(party, aux_pf_it->second);
  }

  for (PartyIndex self_id : fixture.signers) {
    const auto keygen_it = keygen_results.find(self_id);
    if (keygen_it == keygen_results.end()) {
      throw std::runtime_error("missing keygen result for signer");
    }

    SignSessionConfig cfg;
    cfg.session_id = sign_session_id;
    cfg.keygen_session_id = baseline_it->second.keygen_session_id;
    cfg.self_id = self_id;
    cfg.participants = fixture.signers;
    cfg.timeout = std::chrono::seconds(10);
    cfg.x_i = keygen_it->second.x_i;
    cfg.y = baseline_it->second.y;
    cfg.all_X_i = all_X_i_subset;
    cfg.all_paillier_public = paillier_public;
    cfg.all_aux_rsa_params = aux_params;
    cfg.all_square_free_proofs = square_free_proofs;
    cfg.all_aux_param_proofs = aux_param_proofs;
    cfg.square_free_proof_profile =
        baseline_it->second.square_free_proof_profile;
    cfg.aux_param_proof_profile = baseline_it->second.aux_param_proof_profile;
    cfg.local_paillier = paillier_private.at(self_id);
    cfg.msg32 = fixture.msg32;
    cfg.strict_mode = baseline_it->second.strict_mode;
    cfg.require_aux_param_proof = baseline_it->second.require_aux_param_proof;
    cfg.fixed_k_i = fixture.fixed_k.at(self_id);
    cfg.fixed_gamma_i = fixture.fixed_gamma.at(self_id);

    configs.push_back(std::move(cfg));
  }

  return configs;
}

std::vector<std::unique_ptr<SignSession>> BuildSignSessions(
    const SignFixture& fixture,
    const std::unordered_map<PartyIndex, KeygenResult>& keygen_results,
    const Bytes& sign_session_id) {
  std::vector<SignSessionConfig> configs =
      BuildSignSessionConfigs(fixture, keygen_results, sign_session_id);

  std::vector<std::unique_ptr<SignSession>> sessions;
  sessions.reserve(configs.size());
  for (SignSessionConfig& cfg : configs) {
    sessions.push_back(std::make_unique<SignSession>(std::move(cfg)));
  }
  return sessions;
}

bool DeliverSignEnvelope(const Envelope& envelope,
                         const std::vector<PartyIndex>& signers,
                         std::vector<std::unique_ptr<SignSession>>* sessions) {
  bool ok = true;

  if (envelope.to == tecdsa::kBroadcastPartyId) {
    for (size_t idx = 0; idx < signers.size(); ++idx) {
      if (signers[idx] == envelope.from) {
        continue;
      }
      if (!(*sessions)[idx]->HandleEnvelope(envelope)) {
        ok = false;
      }
    }
    return ok;
  }

  const size_t receiver_idx = FindPartyIndexOrThrow(signers, envelope.to);
  if (!(*sessions)[receiver_idx]->HandleEnvelope(envelope)) {
    ok = false;
  }
  return ok;
}

void DeliverSignEnvelopesOrThrow(
    const std::vector<Envelope>& envelopes,
    const std::vector<PartyIndex>& signers,
    std::vector<std::unique_ptr<SignSession>>* sessions) {
  for (const Envelope& envelope : envelopes) {
    if (!DeliverSignEnvelope(envelope, signers, sessions)) {
      throw std::runtime_error("Unexpected sign envelope delivery failure");
    }
  }
}

std::vector<Envelope> CollectPhase1Messages(
    std::vector<std::unique_ptr<SignSession>>* sessions) {
  std::vector<Envelope> out;
  out.reserve(sessions->size());
  for (auto& session : *sessions) {
    out.push_back(session->BuildPhase1CommitEnvelope());
  }
  return out;
}

std::vector<Envelope> CollectPhase2Messages(
    std::vector<std::unique_ptr<SignSession>>* sessions) {
  std::vector<Envelope> out;
  for (auto& session : *sessions) {
    if (session->phase() != SignPhase::kPhase2) {
      continue;
    }
    std::vector<Envelope> batch = session->BuildPhase2MtaEnvelopes();
    out.insert(out.end(), batch.begin(), batch.end());
  }
  return out;
}

std::vector<Envelope> CollectPhase3Messages(
    std::vector<std::unique_ptr<SignSession>>* sessions) {
  std::vector<Envelope> out;
  out.reserve(sessions->size());
  for (auto& session : *sessions) {
    out.push_back(session->BuildPhase3DeltaEnvelope());
  }
  return out;
}

std::vector<Envelope> CollectPhase4Messages(
    std::vector<std::unique_ptr<SignSession>>* sessions) {
  std::vector<Envelope> out;
  out.reserve(sessions->size());
  for (auto& session : *sessions) {
    out.push_back(session->BuildPhase4OpenGammaEnvelope());
  }
  return out;
}

std::vector<Envelope> CollectPhase5AMessages(
    std::vector<std::unique_ptr<SignSession>>* sessions) {
  std::vector<Envelope> out;
  out.reserve(sessions->size());
  for (auto& session : *sessions) {
    out.push_back(session->BuildPhase5ACommitEnvelope());
  }
  return out;
}

std::vector<Envelope> CollectPhase5BMessages(
    std::vector<std::unique_ptr<SignSession>>* sessions) {
  std::vector<Envelope> out;
  out.reserve(sessions->size());
  for (auto& session : *sessions) {
    out.push_back(session->BuildPhase5BOpenEnvelope());
  }
  return out;
}

std::vector<Envelope> CollectPhase5CMessages(
    std::vector<std::unique_ptr<SignSession>>* sessions) {
  std::vector<Envelope> out;
  out.reserve(sessions->size());
  for (auto& session : *sessions) {
    out.push_back(session->BuildPhase5CCommitEnvelope());
  }
  return out;
}

std::vector<Envelope> CollectPhase5DMessages(
    std::vector<std::unique_ptr<SignSession>>* sessions) {
  std::vector<Envelope> out;
  out.reserve(sessions->size());
  for (auto& session : *sessions) {
    out.push_back(session->BuildPhase5DOpenEnvelope());
  }
  return out;
}

std::vector<Envelope> CollectPhase5EMessages(
    std::vector<std::unique_ptr<SignSession>>* sessions) {
  std::vector<Envelope> out;
  out.reserve(sessions->size());
  for (auto& session : *sessions) {
    out.push_back(session->BuildPhase5ERevealEnvelope());
  }
  return out;
}

void EnsureAllSessionsInPhase(
    const std::vector<std::unique_ptr<SignSession>>& sessions, SignPhase phase,
    SignPhase5Stage phase5_stage) {
  for (size_t idx = 0; idx < sessions.size(); ++idx) {
    Expect(sessions[idx]->status() == SessionStatus::kRunning,
           "Sign session should be running before completion/abort");
    Expect(sessions[idx]->phase() == phase,
           "Sign session has unexpected protocol phase");
    if (phase == SignPhase::kPhase5) {
      Expect(sessions[idx]->phase5_stage() == phase5_stage,
             "Sign session has unexpected phase5 sub-stage");
    }
  }
}

void RunToPhase4(std::vector<std::unique_ptr<SignSession>>* sessions,
                 const std::vector<PartyIndex>& signers) {
  DeliverSignEnvelopesOrThrow(CollectPhase1Messages(sessions), signers,
                              sessions);
  EnsureAllSessionsInPhase(*sessions, SignPhase::kPhase2);

  for (size_t round = 0; round < 32; ++round) {
    const std::vector<Envelope> phase2_messages =
        CollectPhase2Messages(sessions);
    if (phase2_messages.empty()) {
      throw std::runtime_error("phase2 stalled before MtA/MtAwc completion");
    }
    DeliverSignEnvelopesOrThrow(phase2_messages, signers, sessions);

    bool all_phase3 = true;
    for (const auto& session : *sessions) {
      if (session->phase() != SignPhase::kPhase3) {
        all_phase3 = false;
        break;
      }
    }
    if (all_phase3) {
      break;
    }
  }
  EnsureAllSessionsInPhase(*sessions, SignPhase::kPhase3);

  DeliverSignEnvelopesOrThrow(CollectPhase3Messages(sessions), signers,
                              sessions);
  EnsureAllSessionsInPhase(*sessions, SignPhase::kPhase4);
}

void RunToPhase5A(std::vector<std::unique_ptr<SignSession>>* sessions,
                  const std::vector<PartyIndex>& signers) {
  RunToPhase4(sessions, signers);

  DeliverSignEnvelopesOrThrow(CollectPhase4Messages(sessions), signers,
                              sessions);
  EnsureAllSessionsInPhase(*sessions, SignPhase::kPhase5,
                           SignPhase5Stage::kPhase5A);
}

void RunToPhase5B(std::vector<std::unique_ptr<SignSession>>* sessions,
                  const std::vector<PartyIndex>& signers) {
  RunToPhase5A(sessions, signers);
  DeliverSignEnvelopesOrThrow(CollectPhase5AMessages(sessions), signers,
                              sessions);
  EnsureAllSessionsInPhase(*sessions, SignPhase::kPhase5,
                           SignPhase5Stage::kPhase5B);
}

void RunToPhase5D(std::vector<std::unique_ptr<SignSession>>* sessions,
                  const std::vector<PartyIndex>& signers) {
  RunToPhase5B(sessions, signers);

  DeliverSignEnvelopesOrThrow(CollectPhase5BMessages(sessions), signers,
                              sessions);
  EnsureAllSessionsInPhase(*sessions, SignPhase::kPhase5,
                           SignPhase5Stage::kPhase5C);

  DeliverSignEnvelopesOrThrow(CollectPhase5CMessages(sessions), signers,
                              sessions);
  EnsureAllSessionsInPhase(*sessions, SignPhase::kPhase5,
                           SignPhase5Stage::kPhase5D);
}

uint32_t ReadU32Be(const Bytes& input, size_t offset) {
  if (offset + 4 > input.size()) {
    throw std::runtime_error("payload is too short to parse u32");
  }
  return (static_cast<uint32_t>(input[offset]) << 24) |
         (static_cast<uint32_t>(input[offset + 1]) << 16) |
         (static_cast<uint32_t>(input[offset + 2]) << 8) |
         static_cast<uint32_t>(input[offset + 3]);
}

bool TamperPhase5BSchnorrProof(Envelope* envelope) {
  if (envelope == nullptr) {
    return false;
  }
  size_t offset = 0;
  constexpr size_t kPointLen = 33;
  constexpr size_t kScalarLen = 32;

  if (envelope->payload.size() < kPointLen * 2 + 4 + kPointLen + kScalarLen) {
    return false;
  }
  offset += kPointLen;  // V_i
  offset += kPointLen;  // A_i
  const uint32_t randomness_len = ReadU32Be(envelope->payload, offset);
  offset += 4;
  if (offset + randomness_len + kPointLen + kScalarLen >
      envelope->payload.size()) {
    return false;
  }
  offset += randomness_len;
  offset += kPointLen;  // Schnorr A

  envelope->payload[offset + kScalarLen - 1] ^= 0x01;  // Schnorr z
  return true;
}

bool ReplacePhase4GammaPoint(Envelope* envelope,
                             std::span<const uint8_t> replacement_point) {
  constexpr size_t kPointLen = 33;
  if (envelope == nullptr || replacement_point.size() != kPointLen ||
      envelope->payload.size() < kPointLen) {
    return false;
  }
  std::copy(replacement_point.begin(), replacement_point.end(),
            envelope->payload.begin());
  return true;
}

bool ReplacePhase5BVPoint(Envelope* envelope,
                          std::span<const uint8_t> replacement_point) {
  constexpr size_t kPointLen = 33;
  if (envelope == nullptr || replacement_point.size() != kPointLen ||
      envelope->payload.size() < kPointLen) {
    return false;
  }
  std::copy(replacement_point.begin(), replacement_point.end(),
            envelope->payload.begin());
  return true;
}

}  // namespace tecdsa::sign_flow_test
