#include <chrono>
#include <cstdint>
#include <iostream>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

#include "yacl/crypto/experimental/threshold_ecdsa/crypto/encoding.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/strict_proofs.h"
#include "yacl/crypto/experimental/threshold_ecdsa/net/envelope.h"
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/keygen_session.h"

namespace {

using tecdsa::Bytes;
using tecdsa::BigInt;
using tecdsa::Envelope;
using tecdsa::KeygenPhase;
using tecdsa::KeygenResult;
using tecdsa::KeygenSession;
using tecdsa::KeygenSessionConfig;
using tecdsa::PartyIndex;
using tecdsa::Scalar;
using tecdsa::SessionStatus;

void Expect(bool condition, const std::string& message) {
  if (!condition) {
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

std::vector<std::unique_ptr<KeygenSession>> BuildSessions(uint32_t n,
                                                          uint32_t t,
                                                          const Bytes& session_id,
                                                          bool strict_mode = true) {
  std::vector<std::unique_ptr<KeygenSession>> sessions;
  sessions.reserve(n);
  const std::vector<PartyIndex> participants = BuildParticipants(n);

  for (PartyIndex self_id : participants) {
    KeygenSessionConfig cfg;
    cfg.session_id = session_id;
    cfg.self_id = self_id;
    cfg.participants = participants;
    cfg.threshold = t;
    cfg.strict_mode = strict_mode;
    cfg.require_aux_param_proof = strict_mode;
    cfg.timeout = std::chrono::seconds(10);
    sessions.push_back(std::make_unique<KeygenSession>(std::move(cfg)));
  }
  return sessions;
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

Bytes TruncatePhase1PayloadToLegacy(const Bytes& payload) {
  if (payload.size() < 32 + 4) {
    throw std::runtime_error("phase1 payload too short to truncate");
  }
  const uint32_t n_len = ReadU32Be(payload, 32);
  const size_t keep_len = 32 + 4 + n_len;
  if (keep_len > payload.size()) {
    throw std::runtime_error("phase1 payload malformed while truncating");
  }
  return Bytes(payload.begin(), payload.begin() + static_cast<std::ptrdiff_t>(keep_len));
}

Bytes TruncatePhase3PayloadWithoutSquareFreeProof(const Bytes& payload) {
  constexpr size_t kPhase3BaseLen = 33 + 33 + 32;
  if (payload.size() < kPhase3BaseLen) {
    throw std::runtime_error("phase3 payload too short to truncate");
  }
  return Bytes(payload.begin(), payload.begin() + static_cast<std::ptrdiff_t>(kPhase3BaseLen));
}

void AppendU32Be(uint32_t value, Bytes* out) {
  out->push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
  out->push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
  out->push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
  out->push_back(static_cast<uint8_t>(value & 0xFF));
}

size_t SkipSizedField(const Bytes& payload, size_t offset, const char* field_name) {
  const uint32_t len = ReadU32Be(payload, offset);
  offset += 4;
  if (offset + len > payload.size()) {
    throw std::runtime_error(std::string("phase1 payload malformed while parsing ") + field_name);
  }
  return offset + len;
}

Bytes RewritePhase1AuxProofAsLegacyBlob(const Bytes& payload) {
  if (payload.size() < 32 + 4) {
    throw std::runtime_error("phase1 payload too short to rewrite aux proof");
  }

  size_t offset = 32;
  offset = SkipSizedField(payload, offset, "Paillier N");
  offset = SkipSizedField(payload, offset, "aux Ntilde");
  offset = SkipSizedField(payload, offset, "aux h1");
  offset = SkipSizedField(payload, offset, "aux h2");
  if (offset + 4 > payload.size()) {
    throw std::runtime_error("phase1 payload missing aux proof length");
  }
  const size_t proof_len_offset = offset;
  const uint32_t proof_len = ReadU32Be(payload, offset);
  offset += 4;
  if (offset + proof_len != payload.size()) {
    throw std::runtime_error("phase1 payload has malformed aux proof field");
  }

  const std::span<const uint8_t> encoded_proof(payload.data() + offset, proof_len);
  const tecdsa::AuxRsaParamProof decoded = tecdsa::DecodeAuxRsaParamProof(encoded_proof);
  if (decoded.blob.empty()) {
    throw std::runtime_error("decoded aux proof blob unexpectedly empty");
  }

  Bytes out;
  out.reserve(payload.size());
  out.insert(out.end(), payload.begin(), payload.begin() + static_cast<std::ptrdiff_t>(proof_len_offset));
  AppendU32Be(static_cast<uint32_t>(decoded.blob.size()), &out);
  out.insert(out.end(), decoded.blob.begin(), decoded.blob.end());
  return out;
}

void TamperPhase1AuxProof(Bytes* payload) {
  if (payload == nullptr || payload->size() < 32 + 4) {
    throw std::runtime_error("phase1 payload too short to tamper aux proof");
  }

  size_t offset = 32;
  offset = SkipSizedField(*payload, offset, "Paillier N");
  offset = SkipSizedField(*payload, offset, "aux Ntilde");
  offset = SkipSizedField(*payload, offset, "aux h1");
  offset = SkipSizedField(*payload, offset, "aux h2");
  if (offset + 4 > payload->size()) {
    throw std::runtime_error("phase1 payload missing aux proof length");
  }
  const uint32_t proof_len = ReadU32Be(*payload, offset);
  offset += 4;
  if (proof_len == 0 || offset + proof_len != payload->size()) {
    throw std::runtime_error("phase1 payload has malformed aux proof field");
  }
  (*payload)[offset + proof_len - 1] ^= 0x01;
}

void CorruptPhase1AuxH1(Bytes* payload) {
  if (payload == nullptr || payload->size() < 32 + 4) {
    throw std::runtime_error("phase1 payload too short to tamper aux h1");
  }

  size_t offset = 32;
  offset = SkipSizedField(*payload, offset, "Paillier N");
  offset = SkipSizedField(*payload, offset, "aux Ntilde");
  if (offset + 4 > payload->size()) {
    throw std::runtime_error("phase1 payload missing aux h1 length");
  }
  const uint32_t h1_len = ReadU32Be(*payload, offset);
  offset += 4;
  if (h1_len == 0 || offset + h1_len > payload->size()) {
    throw std::runtime_error("phase1 payload has malformed aux h1 field");
  }

  std::fill(payload->begin() + static_cast<std::ptrdiff_t>(offset),
            payload->begin() + static_cast<std::ptrdiff_t>(offset + h1_len),
            static_cast<uint8_t>(0x00));
}

void TamperPhase3SquareFreeProof(Bytes* payload) {
  constexpr size_t kPhase3BaseLen = 33 + 33 + 32;
  if (payload == nullptr || payload->size() < kPhase3BaseLen + 4) {
    throw std::runtime_error("phase3 payload too short to tamper square-free proof");
  }

  size_t offset = kPhase3BaseLen;
  const uint32_t proof_len = ReadU32Be(*payload, offset);
  offset += 4;
  if (proof_len == 0 || offset + proof_len != payload->size()) {
    throw std::runtime_error("phase3 payload has malformed square-free proof field");
  }
  (*payload)[offset + proof_len - 1] ^= 0x01;
}

bool DeliverEnvelope(const Envelope& envelope,
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

std::vector<Envelope> BuildAndCollectPhase1(
    std::vector<std::unique_ptr<KeygenSession>>* sessions) {
  std::vector<Envelope> out;
  out.reserve(sessions->size());
  for (auto& session : *sessions) {
    out.push_back(session->BuildPhase1CommitEnvelope());
  }
  return out;
}

std::vector<Envelope> BuildAndCollectPhase2(
    std::vector<std::unique_ptr<KeygenSession>>* sessions) {
  std::vector<Envelope> out;
  for (auto& session : *sessions) {
    const std::vector<Envelope> phase2 = session->BuildPhase2OpenAndShareEnvelopes();
    out.insert(out.end(), phase2.begin(), phase2.end());
  }
  return out;
}

std::vector<Envelope> BuildAndCollectPhase3(
    std::vector<std::unique_ptr<KeygenSession>>* sessions) {
  std::vector<Envelope> out;
  out.reserve(sessions->size());
  for (auto& session : *sessions) {
    out.push_back(session->BuildPhase3XiProofEnvelope());
  }
  return out;
}

void EnsureAllSessionsInPhase(const std::vector<std::unique_ptr<KeygenSession>>& sessions,
                              KeygenPhase phase) {
  for (size_t idx = 0; idx < sessions.size(); ++idx) {
    const PartyIndex id = static_cast<PartyIndex>(idx + 1);
    Expect(sessions[idx]->status() == SessionStatus::kRunning,
           "Session " + std::to_string(id) + " must be running");
    Expect(sessions[idx]->phase() == phase,
           "Session " + std::to_string(id) + " has unexpected phase");
  }
}

void EnsureAllSessionsCompleted(const std::vector<std::unique_ptr<KeygenSession>>& sessions) {
  for (size_t idx = 0; idx < sessions.size(); ++idx) {
    const PartyIndex id = static_cast<PartyIndex>(idx + 1);
    Expect(sessions[idx]->status() == SessionStatus::kCompleted,
           "Session " + std::to_string(id) + " must complete");
    Expect(sessions[idx]->phase() == KeygenPhase::kCompleted,
           "Session " + std::to_string(id) + " must be in completed phase");
    Expect(sessions[idx]->HasResult(),
           "Session " + std::to_string(id) + " must expose a completed keygen result");
  }
}

void DeliverEnvelopesOrThrow(const std::vector<Envelope>& messages,
                             std::vector<std::unique_ptr<KeygenSession>>* sessions) {
  for (const Envelope& envelope : messages) {
    if (!DeliverEnvelope(envelope, sessions)) {
      throw std::runtime_error("Envelope delivery failed unexpectedly");
    }
  }
}

void AssertKeygenOutputsConsistent(const std::vector<std::unique_ptr<KeygenSession>>& sessions,
                                   uint32_t n) {
  const KeygenResult& baseline = sessions.front()->result();
  Expect(baseline.all_X_i.size() == n, "Baseline keygen result must contain all X_i values");
  Expect(baseline.all_paillier_public.size() == n,
         "Baseline keygen result must contain all Paillier public keys");
  Expect(baseline.all_aux_rsa_params.size() == n,
         "Baseline keygen result must contain all auxiliary RSA parameters");
  Expect(baseline.local_paillier != nullptr,
         "Baseline keygen result must expose local Paillier provider");

  BigInt min_paillier_n(1);
  for (size_t i = 0; i < 8; ++i) {
    min_paillier_n *= Scalar::ModulusQMpInt();
  }

  for (size_t idx = 0; idx < sessions.size(); ++idx) {
    const PartyIndex self_id = static_cast<PartyIndex>(idx + 1);
    const KeygenResult& current = sessions[idx]->result();

    Expect(current.y == baseline.y,
           "All sessions must derive the same group public key y");
    Expect(current.all_X_i.size() == baseline.all_X_i.size(),
           "All sessions must agree on the number of public shares");
    Expect(current.all_paillier_public.size() == baseline.all_paillier_public.size(),
           "All sessions must agree on the number of Paillier public keys");
    Expect(current.all_aux_rsa_params.size() == baseline.all_aux_rsa_params.size(),
           "All sessions must agree on auxiliary RSA parameter count");
    Expect(current.local_paillier != nullptr,
           "Each session result must expose local Paillier provider");

    for (const auto& [party_id, expected_x_i] : baseline.all_X_i) {
      const auto it = current.all_X_i.find(party_id);
      Expect(it != current.all_X_i.end(),
             "Session result is missing X_i for party " + std::to_string(party_id));
      Expect(it->second == expected_x_i,
             "Session result has mismatched X_i for party " + std::to_string(party_id));
    }

    const auto self_it = current.all_X_i.find(self_id);
    Expect(self_it != current.all_X_i.end(),
           "Session result must contain its own X_i entry");
    Expect(self_it->second == current.X_i,
           "Session result must expose X_i equal to all_X_i[self]");

    for (const auto& [party_id, expected_pub] : baseline.all_paillier_public) {
      const auto it = current.all_paillier_public.find(party_id);
      Expect(it != current.all_paillier_public.end(),
             "Session result is missing Paillier public key for party " + std::to_string(party_id));
      Expect(it->second.n == expected_pub.n,
             "Session result has mismatched Paillier modulus for party " + std::to_string(party_id));
      const BigInt party_n = it->second.n;
      Expect(party_n > min_paillier_n,
             "Session result has Paillier modulus that does not satisfy N > q^8");
    }

    for (const auto& [party_id, expected_aux] : baseline.all_aux_rsa_params) {
      const auto aux_it = current.all_aux_rsa_params.find(party_id);
      Expect(aux_it != current.all_aux_rsa_params.end(),
             "Session result is missing auxiliary RSA parameters for party " +
                 std::to_string(party_id));
      Expect(aux_it->second.n_tilde == expected_aux.n_tilde,
             "Session result has mismatched aux Ntilde for party " + std::to_string(party_id));
      Expect(aux_it->second.h1 == expected_aux.h1,
             "Session result has mismatched aux h1 for party " + std::to_string(party_id));
      Expect(aux_it->second.h2 == expected_aux.h2,
             "Session result has mismatched aux h2 for party " + std::to_string(party_id));
      if (baseline.strict_mode) {
        const auto square_it = current.all_square_free_proofs.find(party_id);
        const auto aux_pf_it = current.all_aux_param_proofs.find(party_id);
        tecdsa::StrictProofVerifierContext proof_ctx;
        proof_ctx.session_id = current.keygen_session_id;
        proof_ctx.prover_id = party_id;
        Expect(square_it != current.all_square_free_proofs.end(),
               "Strict keygen result must include square-free proof for party " +
                   std::to_string(party_id));
        Expect(square_it->second.metadata.scheme == tecdsa::StrictProofScheme::kSquareFreeGmr98V1,
               "Strict keygen result must use GMR98 square-free proof scheme");
        Expect(aux_pf_it != current.all_aux_param_proofs.end(),
               "Strict keygen result must include aux param proof for party " +
                   std::to_string(party_id));
        Expect(tecdsa::VerifySquareFreeProof(
                   current.all_paillier_public.at(party_id).n,
                   square_it->second,
                   proof_ctx),
               "Strict keygen result must include a valid square-free proof");
        Expect(tecdsa::VerifyAuxRsaParamProof(aux_it->second, aux_pf_it->second, proof_ctx),
               "Strict keygen result must include a valid aux param proof");
      }
    }

    const auto self_paillier_it = current.all_paillier_public.find(self_id);
    Expect(self_paillier_it != current.all_paillier_public.end(),
           "Session result must contain its own Paillier public key entry");
    const BigInt self_paillier_n = self_paillier_it->second.n;
    Expect(self_paillier_n == current.local_paillier->modulus_n_bigint(),
           "Session local Paillier private key must match broadcast public key");
  }
}

void RunHonestKeygenAndAssertConsistency(uint32_t n, uint32_t t, const Bytes& session_id) {
  auto sessions = BuildSessions(n, t, session_id);

  const std::vector<Envelope> phase1 = BuildAndCollectPhase1(&sessions);
  DeliverEnvelopesOrThrow(phase1, &sessions);
  EnsureAllSessionsInPhase(sessions, KeygenPhase::kPhase2);

  const std::vector<Envelope> phase2 = BuildAndCollectPhase2(&sessions);
  DeliverEnvelopesOrThrow(phase2, &sessions);
  EnsureAllSessionsInPhase(sessions, KeygenPhase::kPhase3);

  const std::vector<Envelope> phase3 = BuildAndCollectPhase3(&sessions);
  DeliverEnvelopesOrThrow(phase3, &sessions);
  EnsureAllSessionsCompleted(sessions);
  AssertKeygenOutputsConsistent(sessions, n);
}

void TestKeygenConsistencyN3T1() {
  RunHonestKeygenAndAssertConsistency(/*n=*/3, /*t=*/1, Bytes{0xA1, 0x03, 0x01});
}

void TestKeygenConsistencyN5T2() {
  RunHonestKeygenAndAssertConsistency(/*n=*/5, /*t=*/2, Bytes{0xA1, 0x05, 0x02});
}

void TestTamperedPhase2ShareAbortsReceiver() {
  auto sessions = BuildSessions(/*n=*/3, /*t=*/1, Bytes{0xB1, 0x03, 0x01});

  const std::vector<Envelope> phase1 = BuildAndCollectPhase1(&sessions);
  DeliverEnvelopesOrThrow(phase1, &sessions);
  EnsureAllSessionsInPhase(sessions, KeygenPhase::kPhase2);

  std::vector<Envelope> phase2 = BuildAndCollectPhase2(&sessions);
  bool tampered = false;
  for (Envelope& envelope : phase2) {
    if (envelope.type == KeygenSession::Phase2ShareMessageType() && envelope.from == 1 &&
        envelope.to == 2) {
      envelope.payload.back() ^= 0x01;
      tampered = true;
      break;
    }
  }
  Expect(tampered, "Test setup failed to locate a phase2 share to tamper");

  for (const Envelope& envelope : phase2) {
    (void)DeliverEnvelope(envelope, &sessions);
  }

  Expect(sessions[1]->status() == SessionStatus::kAborted,
         "Receiver must abort when a dealer share is tampered");
}

void TestTamperedPhase1PaillierModulusAbortsReceiver() {
  auto sessions = BuildSessions(/*n=*/3, /*t=*/1, Bytes{0xB2, 0x03, 0x01});

  std::vector<Envelope> phase1 = BuildAndCollectPhase1(&sessions);
  bool tampered = false;
  for (Envelope& envelope : phase1) {
    if (envelope.from != 1) {
      continue;
    }

    Bytes malformed_payload;
    malformed_payload.insert(malformed_payload.end(), envelope.payload.begin(), envelope.payload.begin() + 32);

    const Bytes tiny_n = tecdsa::EncodeMpInt(BigInt(17));
    auto append_u32 = [](uint32_t value, Bytes* out) {
      out->push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
      out->push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
      out->push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
      out->push_back(static_cast<uint8_t>(value & 0xFF));
    };
    append_u32(static_cast<uint32_t>(tiny_n.size()), &malformed_payload);
    malformed_payload.insert(malformed_payload.end(), tiny_n.begin(), tiny_n.end());

    envelope.payload = std::move(malformed_payload);
    tampered = true;
    break;
  }
  Expect(tampered, "Test setup failed to locate a phase1 payload to tamper");

  for (const Envelope& envelope : phase1) {
    (void)DeliverEnvelope(envelope, &sessions);
  }

  Expect(sessions[1]->status() == SessionStatus::kAborted,
         "Peer 2 must abort when phase1 Paillier modulus is too small");
  Expect(sessions[2]->status() == SessionStatus::kAborted,
         "Peer 3 must abort when phase1 Paillier modulus is too small");
}

void TestTamperedPhase3SchnorrAbortsPeers() {
  auto sessions = BuildSessions(/*n=*/3, /*t=*/1, Bytes{0xC1, 0x03, 0x01});

  const std::vector<Envelope> phase1 = BuildAndCollectPhase1(&sessions);
  DeliverEnvelopesOrThrow(phase1, &sessions);
  const std::vector<Envelope> phase2 = BuildAndCollectPhase2(&sessions);
  DeliverEnvelopesOrThrow(phase2, &sessions);
  EnsureAllSessionsInPhase(sessions, KeygenPhase::kPhase3);

  std::vector<Envelope> phase3 = BuildAndCollectPhase3(&sessions);
  bool tampered = false;
  for (Envelope& envelope : phase3) {
    if (envelope.from == 1 &&
        envelope.type == KeygenSession::MessageTypeForPhase(KeygenPhase::kPhase3)) {
      envelope.payload.back() ^= 0x01;
      tampered = true;
      break;
    }
  }
  Expect(tampered, "Test setup failed to locate a phase3 proof to tamper");

  for (const Envelope& envelope : phase3) {
    (void)DeliverEnvelope(envelope, &sessions);
  }

  Expect(sessions[1]->status() == SessionStatus::kAborted,
         "Peer 2 must abort when Schnorr proof is tampered");
  Expect(sessions[2]->status() == SessionStatus::kAborted,
         "Peer 3 must abort when Schnorr proof is tampered");
}

void TestStrictModeMissingPhase1AuxProofAbortsReceiver() {
  auto sessions = BuildSessions(/*n=*/3, /*t=*/1, Bytes{0xC2, 0x03, 0x01}, /*strict_mode=*/true);

  std::vector<Envelope> phase1 = BuildAndCollectPhase1(&sessions);
  bool tampered = false;
  for (Envelope& envelope : phase1) {
    if (envelope.from == 1) {
      envelope.payload = TruncatePhase1PayloadToLegacy(envelope.payload);
      tampered = true;
      break;
    }
  }
  Expect(tampered, "Test setup failed to locate a phase1 payload to drop strict proofs");

  for (const Envelope& envelope : phase1) {
    (void)DeliverEnvelope(envelope, &sessions);
  }

  Expect(sessions[1]->status() == SessionStatus::kAborted,
         "Strict receiver must abort when phase1 aux proof is missing");
  Expect(sessions[2]->status() == SessionStatus::kAborted,
         "Strict receiver must abort when phase1 aux proof is missing");
}

void TestStrictModeLegacyAuxProofEncodingAbortsReceiver() {
  auto sessions = BuildSessions(/*n=*/3, /*t=*/1, Bytes{0xC6, 0x03, 0x01}, /*strict_mode=*/true);

  std::vector<Envelope> phase1 = BuildAndCollectPhase1(&sessions);
  bool tampered = false;
  for (Envelope& envelope : phase1) {
    if (envelope.from == 1) {
      envelope.payload = RewritePhase1AuxProofAsLegacyBlob(envelope.payload);
      tampered = true;
      break;
    }
  }
  Expect(tampered, "Test setup failed to locate a phase1 payload to rewrite aux proof encoding");

  for (const Envelope& envelope : phase1) {
    (void)DeliverEnvelope(envelope, &sessions);
  }

  Expect(sessions[1]->status() == SessionStatus::kAborted,
         "Strict receiver must abort on legacy aux proof encoding");
  Expect(sessions[2]->status() == SessionStatus::kAborted,
         "Strict receiver must abort on legacy aux proof encoding");
}

void TestStrictModeTamperedPhase1AuxProofAbortsReceiver() {
  auto sessions = BuildSessions(/*n=*/3, /*t=*/1, Bytes{0xC7, 0x03, 0x01}, /*strict_mode=*/true);

  std::vector<Envelope> phase1 = BuildAndCollectPhase1(&sessions);
  bool tampered = false;
  for (Envelope& envelope : phase1) {
    if (envelope.from == 1) {
      TamperPhase1AuxProof(&envelope.payload);
      tampered = true;
      break;
    }
  }
  Expect(tampered, "Test setup failed to locate a phase1 payload to tamper aux proof");

  for (const Envelope& envelope : phase1) {
    (void)DeliverEnvelope(envelope, &sessions);
  }

  Expect(sessions[1]->status() == SessionStatus::kAborted,
         "Strict receiver must abort on tampered phase1 aux proof");
  Expect(sessions[2]->status() == SessionStatus::kAborted,
         "Strict receiver must abort on tampered phase1 aux proof");
}

void TestStrictModeMalformedAuxParamsProofMismatchAbortsReceiver() {
  auto sessions = BuildSessions(/*n=*/3, /*t=*/1, Bytes{0xC8, 0x03, 0x01}, /*strict_mode=*/true);

  std::vector<Envelope> phase1 = BuildAndCollectPhase1(&sessions);
  bool tampered = false;
  for (Envelope& envelope : phase1) {
    if (envelope.from == 1) {
      CorruptPhase1AuxH1(&envelope.payload);
      tampered = true;
      break;
    }
  }
  Expect(tampered, "Test setup failed to locate a phase1 payload to corrupt aux parameters");

  for (const Envelope& envelope : phase1) {
    (void)DeliverEnvelope(envelope, &sessions);
  }

  Expect(sessions[1]->status() == SessionStatus::kAborted,
         "Strict receiver must abort on malformed aux parameters");
  Expect(sessions[2]->status() == SessionStatus::kAborted,
         "Strict receiver must abort on malformed aux parameters");
}

void TestStrictModeMissingPhase3SquareFreeProofAbortsReceiver() {
  auto sessions = BuildSessions(/*n=*/3, /*t=*/1, Bytes{0xC4, 0x03, 0x01}, /*strict_mode=*/true);

  const std::vector<Envelope> phase1 = BuildAndCollectPhase1(&sessions);
  DeliverEnvelopesOrThrow(phase1, &sessions);
  const std::vector<Envelope> phase2 = BuildAndCollectPhase2(&sessions);
  DeliverEnvelopesOrThrow(phase2, &sessions);
  EnsureAllSessionsInPhase(sessions, KeygenPhase::kPhase3);

  std::vector<Envelope> phase3 = BuildAndCollectPhase3(&sessions);
  bool tampered = false;
  for (Envelope& envelope : phase3) {
    if (envelope.from == 1) {
      envelope.payload = TruncatePhase3PayloadWithoutSquareFreeProof(envelope.payload);
      tampered = true;
      break;
    }
  }
  Expect(tampered, "Test setup failed to locate a phase3 payload to drop square-free proof");

  for (const Envelope& envelope : phase3) {
    (void)DeliverEnvelope(envelope, &sessions);
  }

  Expect(sessions[1]->status() == SessionStatus::kAborted,
         "Strict receiver must abort when phase3 square-free proof is missing");
  Expect(sessions[2]->status() == SessionStatus::kAborted,
         "Strict receiver must abort when phase3 square-free proof is missing");
}

void TestStrictModeTamperedPhase3SquareFreeProofAbortsReceiver() {
  auto sessions = BuildSessions(/*n=*/3, /*t=*/1, Bytes{0xC9, 0x03, 0x01}, /*strict_mode=*/true);

  const std::vector<Envelope> phase1 = BuildAndCollectPhase1(&sessions);
  DeliverEnvelopesOrThrow(phase1, &sessions);
  const std::vector<Envelope> phase2 = BuildAndCollectPhase2(&sessions);
  DeliverEnvelopesOrThrow(phase2, &sessions);
  EnsureAllSessionsInPhase(sessions, KeygenPhase::kPhase3);

  std::vector<Envelope> phase3 = BuildAndCollectPhase3(&sessions);
  bool tampered = false;
  for (Envelope& envelope : phase3) {
    if (envelope.from == 1) {
      TamperPhase3SquareFreeProof(&envelope.payload);
      tampered = true;
      break;
    }
  }
  Expect(tampered, "Test setup failed to locate a phase3 payload to tamper square-free proof");

  for (const Envelope& envelope : phase3) {
    (void)DeliverEnvelope(envelope, &sessions);
  }

  Expect(sessions[1]->status() == SessionStatus::kAborted,
         "Strict receiver must abort on tampered phase3 square-free proof");
  Expect(sessions[2]->status() == SessionStatus::kAborted,
         "Strict receiver must abort on tampered phase3 square-free proof");
}

void TestDevModeAcceptsLegacyPhase1WithoutProofs() {
  auto sessions = BuildSessions(/*n=*/3, /*t=*/1, Bytes{0xC3, 0x03, 0x01}, /*strict_mode=*/false);

  std::vector<Envelope> phase1 = BuildAndCollectPhase1(&sessions);
  bool tampered = false;
  for (Envelope& envelope : phase1) {
    if (envelope.from == 1) {
      envelope.payload = TruncatePhase1PayloadToLegacy(envelope.payload);
      tampered = true;
      break;
    }
  }
  Expect(tampered, "Test setup failed to locate a phase1 payload to downgrade");
  DeliverEnvelopesOrThrow(phase1, &sessions);
  EnsureAllSessionsInPhase(sessions, KeygenPhase::kPhase2);

  const std::vector<Envelope> phase2 = BuildAndCollectPhase2(&sessions);
  DeliverEnvelopesOrThrow(phase2, &sessions);
  EnsureAllSessionsInPhase(sessions, KeygenPhase::kPhase3);

  const std::vector<Envelope> phase3 = BuildAndCollectPhase3(&sessions);
  DeliverEnvelopesOrThrow(phase3, &sessions);
  EnsureAllSessionsCompleted(sessions);
  for (const auto& session : sessions) {
    Expect(!session->result().strict_mode, "Dev-mode keygen result should carry strict_mode=false");
  }
}

}  // namespace

int main() {
  try {
    TestKeygenConsistencyN3T1();
    TestKeygenConsistencyN5T2();
    TestTamperedPhase1PaillierModulusAbortsReceiver();
    TestTamperedPhase2ShareAbortsReceiver();
    TestTamperedPhase3SchnorrAbortsPeers();
    TestStrictModeMissingPhase1AuxProofAbortsReceiver();
    TestStrictModeLegacyAuxProofEncodingAbortsReceiver();
    TestStrictModeTamperedPhase1AuxProofAbortsReceiver();
    TestStrictModeMalformedAuxParamsProofMismatchAbortsReceiver();
    TestStrictModeMissingPhase3SquareFreeProofAbortsReceiver();
    TestStrictModeTamperedPhase3SquareFreeProofAbortsReceiver();
    TestDevModeAcceptsLegacyPhase1WithoutProofs();
  } catch (const std::exception& ex) {
    std::cerr << ex.what() << '\n';
    return 1;
  }

  std::cout << "keygen_flow_tests passed" << '\n';
  return 0;
}
