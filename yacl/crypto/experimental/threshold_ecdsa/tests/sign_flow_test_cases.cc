#include "sign_flow_test_shared.h"

namespace tecdsa::sign_flow_test {

void TestStage4SignConstructorRejectsSmallPaillierModulus() {
  const auto keygen_results = RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xD0, 0x03, 0x02});
  const std::vector<PartyIndex> signers = {1, 2};
  const SignFixture fixture = BuildSignFixture(signers);
  std::vector<SignSessionConfig> configs =
      BuildSignSessionConfigs(fixture, keygen_results, Bytes{0xE0, 0x02, 0x02});

  const size_t cfg_idx = FindPartyIndexOrThrow(signers, 1);
  SignSessionConfig bad_cfg = std::move(configs[cfg_idx]);
  bad_cfg.all_paillier_public.at(2).n = tecdsa::BigInt(17);

  ExpectThrow([&]() { (void)SignSession(std::move(bad_cfg)); },
              "SignSession must reject participant Paillier modulus N <= q^8");
}

void TestStage6SignConstructorRejectsMissingKeygenProofArtifacts() {
  const auto keygen_results = RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xDE, 0x03, 0x01});
  const std::vector<PartyIndex> signers = {1, 2};
  const SignFixture fixture = BuildSignFixture(signers);
  std::vector<SignSessionConfig> configs =
      BuildSignSessionConfigs(fixture, keygen_results, Bytes{0xEE, 0x02, 0x01});

  const size_t cfg_idx = FindPartyIndexOrThrow(signers, 1);
  SignSessionConfig missing_cfg = configs[cfg_idx];
  missing_cfg.all_square_free_proofs.clear();
  missing_cfg.all_aux_param_proofs.clear();

  ExpectThrow([&]() { (void)SignSession(std::move(missing_cfg)); },
              "strict SignSession must reject missing keygen proof artifacts");
}

void TestStage6SignConstructorRejectsInvalidKeygenProofArtifacts() {
  const auto keygen_results = RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xDF, 0x03, 0x01});
  const std::vector<PartyIndex> signers = {1, 2};
  const SignFixture fixture = BuildSignFixture(signers);
  std::vector<SignSessionConfig> configs =
      BuildSignSessionConfigs(fixture, keygen_results, Bytes{0xEF, 0x02, 0x01});

  const size_t cfg_idx = FindPartyIndexOrThrow(signers, 1);

  SignSessionConfig bad_square_cfg = configs[cfg_idx];
  auto square_it = bad_square_cfg.all_square_free_proofs.find(2);
  if (square_it == bad_square_cfg.all_square_free_proofs.end() || square_it->second.blob.empty()) {
    throw std::runtime_error("test setup missing square-free proof blob to tamper");
  }
  square_it->second.blob.back() ^= 0x01;
  ExpectThrow([&]() { (void)SignSession(std::move(bad_square_cfg)); },
              "strict SignSession must reject invalid square-free keygen proof");

  SignSessionConfig bad_aux_cfg = configs[cfg_idx];
  auto aux_it = bad_aux_cfg.all_aux_param_proofs.find(2);
  if (aux_it == bad_aux_cfg.all_aux_param_proofs.end() || aux_it->second.blob.empty()) {
    throw std::runtime_error("test setup missing aux proof blob to tamper");
  }
  aux_it->second.blob.back() ^= 0x01;
  ExpectThrow([&]() { (void)SignSession(std::move(bad_aux_cfg)); },
              "strict SignSession must reject invalid aux keygen proof");
}

void TestStage6MalformedPhase2InitProofPayloadAbortsResponder() {
  const auto keygen_results = RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xE0, 0x03, 0x01});
  const std::vector<PartyIndex> signers = {1, 2};
  const SignFixture fixture = BuildSignFixture(signers);
  auto sessions = BuildSignSessions(fixture, keygen_results, Bytes{0xF0, 0x02, 0x01});

  DeliverSignEnvelopesOrThrow(CollectPhase1Messages(&sessions), signers, &sessions);
  EnsureAllSessionsInPhase(sessions, SignPhase::kPhase2);

  std::vector<Envelope> phase2_init = CollectPhase2Messages(&sessions);
  bool tampered = false;
  for (Envelope& envelope : phase2_init) {
    if (envelope.type == SignSession::MessageTypeForPhase(SignPhase::kPhase2) &&
        envelope.from == 1 &&
        envelope.to == 2 &&
        envelope.payload.size() > 1) {
      envelope.payload.resize(envelope.payload.size() - 1);
      tampered = true;
      break;
    }
  }
  Expect(tampered, "Test setup failed to locate phase2 init payload to truncate");

  for (const Envelope& envelope : phase2_init) {
    (void)DeliverSignEnvelope(envelope, signers, &sessions);
  }

  const size_t responder_idx = FindPartyIndexOrThrow(signers, 2);
  Expect(sessions[responder_idx]->status() == SessionStatus::kAborted,
         "Responder must abort on malformed phase2 init proof payload");
  for (const auto& session : sessions) {
    Expect(!session->HasResult(), "Malformed phase2 init payload must not expose signature result");
  }
}

void TestStage6MalformedPhase2ResponseProofPayloadAbortsInitiator() {
  const auto keygen_results = RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xE1, 0x03, 0x01});
  const std::vector<PartyIndex> signers = {1, 2};
  const SignFixture fixture = BuildSignFixture(signers);
  auto sessions = BuildSignSessions(fixture, keygen_results, Bytes{0xF1, 0x02, 0x01});

  DeliverSignEnvelopesOrThrow(CollectPhase1Messages(&sessions), signers, &sessions);
  EnsureAllSessionsInPhase(sessions, SignPhase::kPhase2);
  DeliverSignEnvelopesOrThrow(CollectPhase2Messages(&sessions), signers, &sessions);

  std::vector<Envelope> phase2_responses = CollectPhase2Messages(&sessions);
  bool tampered = false;
  for (Envelope& envelope : phase2_responses) {
    if (envelope.type == SignSession::Phase2ResponseMessageType() &&
        envelope.from == 2 &&
        envelope.to == 1 &&
        envelope.payload.size() > 1) {
      envelope.payload.resize(envelope.payload.size() - 1);
      tampered = true;
      break;
    }
  }
  Expect(tampered, "Test setup failed to locate phase2 response payload to truncate");

  for (const Envelope& envelope : phase2_responses) {
    (void)DeliverSignEnvelope(envelope, signers, &sessions);
  }

  const size_t initiator_idx = FindPartyIndexOrThrow(signers, 1);
  Expect(sessions[initiator_idx]->status() == SessionStatus::kAborted,
         "Initiator must abort on malformed phase2 response proof payload");
  for (const auto& session : sessions) {
    Expect(!session->HasResult(), "Malformed phase2 response payload must not expose signature result");
  }
}

void TestStage4Phase2InitUsesResponderOwnedAuxParams() {
  const auto keygen_results = RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xD0, 0x03, 0x03});
  const std::vector<PartyIndex> signers = {1, 2};
  const SignFixture fixture = BuildSignFixture(signers);
  std::vector<SignSessionConfig> configs =
      BuildSignSessionConfigs(fixture, keygen_results, Bytes{0xE0, 0x02, 0x03});

  const size_t responder_cfg_idx = FindPartyIndexOrThrow(signers, 2);
  SignSessionConfig& responder_cfg = configs[responder_cfg_idx];
  const auto initiator_aux_it = responder_cfg.all_aux_rsa_params.find(1);
  Expect(initiator_aux_it != responder_cfg.all_aux_rsa_params.end(),
         "Responder config must include initiator aux params");
  responder_cfg.all_aux_rsa_params[2] = initiator_aux_it->second;
  responder_cfg.all_aux_param_proofs[2] =
      tecdsa::BuildAuxRsaParamProof(
          initiator_aux_it->second,
          BuildKeygenProofContext(responder_cfg.keygen_session_id, /*prover_id=*/2));

  std::vector<std::unique_ptr<SignSession>> sessions;
  sessions.reserve(configs.size());
  for (SignSessionConfig& cfg : configs) {
    sessions.push_back(std::make_unique<SignSession>(std::move(cfg)));
  }

  DeliverSignEnvelopesOrThrow(CollectPhase1Messages(&sessions), signers, &sessions);
  EnsureAllSessionsInPhase(sessions, SignPhase::kPhase2);

  const std::vector<Envelope> phase2_init = CollectPhase2Messages(&sessions);
  for (const Envelope& envelope : phase2_init) {
    (void)DeliverSignEnvelope(envelope, signers, &sessions);
  }

  const size_t responder_idx = FindPartyIndexOrThrow(signers, 2);
  Expect(sessions[responder_idx]->status() == SessionStatus::kAborted,
         "Responder must abort when A1 verification uses responder-owned aux params");
  for (const auto& session : sessions) {
    Expect(!session->HasResult(), "Stage4 A1 ownership failure must not expose signature result");
  }
}

void TestStage4Phase2ResponseUsesInitiatorOwnedAuxParams() {
  const auto keygen_results = RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xD0, 0x03, 0x04});
  const std::vector<PartyIndex> signers = {1, 2};
  const SignFixture fixture = BuildSignFixture(signers);
  std::vector<SignSessionConfig> configs =
      BuildSignSessionConfigs(fixture, keygen_results, Bytes{0xE0, 0x02, 0x04});

  const size_t responder_cfg_idx = FindPartyIndexOrThrow(signers, 2);
  SignSessionConfig& responder_cfg = configs[responder_cfg_idx];
  const auto self_aux_it = responder_cfg.all_aux_rsa_params.find(2);
  Expect(self_aux_it != responder_cfg.all_aux_rsa_params.end(),
         "Responder config must include self aux params");
  responder_cfg.all_aux_rsa_params[1] = self_aux_it->second;
  responder_cfg.all_aux_param_proofs[1] =
      tecdsa::BuildAuxRsaParamProof(
          self_aux_it->second,
          BuildKeygenProofContext(responder_cfg.keygen_session_id, /*prover_id=*/1));

  std::vector<std::unique_ptr<SignSession>> sessions;
  sessions.reserve(configs.size());
  for (SignSessionConfig& cfg : configs) {
    sessions.push_back(std::make_unique<SignSession>(std::move(cfg)));
  }

  DeliverSignEnvelopesOrThrow(CollectPhase1Messages(&sessions), signers, &sessions);
  EnsureAllSessionsInPhase(sessions, SignPhase::kPhase2);

  const size_t initiator_idx = FindPartyIndexOrThrow(signers, 1);
  const size_t responder_idx = FindPartyIndexOrThrow(signers, 2);

  std::vector<Envelope> initiator_msgs = sessions[initiator_idx]->BuildPhase2MtaEnvelopes();
  size_t delivered_init_count = 0;
  for (const Envelope& envelope : initiator_msgs) {
    if (envelope.type == SignSession::MessageTypeForPhase(SignPhase::kPhase2) &&
        envelope.from == 1 &&
        envelope.to == 2) {
      (void)DeliverSignEnvelope(envelope, signers, &sessions);
      ++delivered_init_count;
    }
  }
  Expect(delivered_init_count > 0, "Test setup failed to deliver any phase2 init envelope");

  std::vector<Envelope> responder_msgs = sessions[responder_idx]->BuildPhase2MtaEnvelopes();
  std::vector<Envelope> responder_responses;
  for (const Envelope& envelope : responder_msgs) {
    if (envelope.type == SignSession::Phase2ResponseMessageType() &&
        envelope.from == 2 &&
        envelope.to == 1) {
      responder_responses.push_back(envelope);
    }
  }
  Expect(!responder_responses.empty(),
         "Phase2 must emit responder responses for A2/A3 ownership checks");
  for (const Envelope& envelope : responder_responses) {
    (void)DeliverSignEnvelope(envelope, signers, &sessions);
  }

  Expect(sessions[initiator_idx]->status() == SessionStatus::kAborted,
         "Initiator must abort when A2/A3 verification uses initiator-owned aux params");
  for (const auto& session : sessions) {
    Expect(!session->HasResult(), "Stage4 A2/A3 ownership failure must not expose signature result");
  }
}

void TestM4SignEndToEndProducesVerifiableSignature() {
  const auto keygen_results = RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xD1, 0x03, 0x01});

  const std::vector<PartyIndex> signers = {1, 2};
  const SignFixture fixture = BuildSignFixture(signers);
  auto sessions = BuildSignSessions(fixture, keygen_results, Bytes{0xE1, 0x02, 0x01});

  RunToPhase5D(&sessions, signers);

  DeliverSignEnvelopesOrThrow(CollectPhase5DMessages(&sessions), signers, &sessions);
  EnsureAllSessionsInPhase(sessions, SignPhase::kPhase5, SignPhase5Stage::kPhase5E);

  DeliverSignEnvelopesOrThrow(CollectPhase5EMessages(&sessions), signers, &sessions);

  const auto& first_result = sessions.front()->result();
  Expect(first_result.r.value() != 0, "Final signature r must be non-zero");
  Expect(first_result.s.value() != 0, "Final signature s must be non-zero");

  for (size_t idx = 0; idx < sessions.size(); ++idx) {
    Expect(sessions[idx]->status() == SessionStatus::kCompleted,
           "Sign session should complete after phase5E");
    Expect(sessions[idx]->phase() == SignPhase::kCompleted,
           "Sign session should be in completed phase");
    Expect(sessions[idx]->HasResult(),
           "Completed sign session should expose result");

    const auto& result = sessions[idx]->result();
    Expect(result.r == first_result.r, "All signers must derive same r");
    Expect(result.s == first_result.s, "All signers must derive same s");
    Expect(result.R == first_result.R, "All signers must derive same R");
    Expect(result.W_points.size() == signers.size(),
           "Result should expose W_i for all signing parties");
  }
}

void TestM4Phase5DFailurePreventsPhase5EReveal() {
  const auto keygen_results = RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xD2, 0x03, 0x01});

  const std::vector<PartyIndex> signers = {1, 2};
  const SignFixture bad_fixture = BuildSignFixture(signers);
  auto sessions = BuildSignSessions(bad_fixture, keygen_results, Bytes{0xE2, 0x02, 0x01});

  RunToPhase5D(&sessions, signers);

  std::vector<Envelope> phase5d = CollectPhase5DMessages(&sessions);
  if (!phase5d.empty() && !phase5d.front().payload.empty()) {
    phase5d.front().payload.back() ^= 0x01;
  }
  for (const Envelope& envelope : phase5d) {
    (void)DeliverSignEnvelope(envelope, signers, &sessions);
  }

  bool any_aborted = false;
  for (const auto& session : sessions) {
    if (session->status() == SessionStatus::kAborted) {
      any_aborted = true;
    }
  }
  Expect(any_aborted, "At least one party must abort at phase5D when open payload is tampered");

  for (auto& session : sessions) {
    if (session->status() == SessionStatus::kAborted) {
      Expect(session->phase() == SignPhase::kPhase5,
             "Aborted session should remain in phase5");
      Expect(session->phase5_stage() == SignPhase5Stage::kPhase5D,
             "Aborted session must stay at phase5D");
      ExpectThrow([&]() { (void)session->BuildPhase5ERevealEnvelope(); },
                  "Aborted session cannot build phase5E reveal envelope");
    } else {
      Expect(session->status() == SessionStatus::kRunning,
             "Non-aborted peers should remain running after remote phase5D failure");
      Expect(session->phase() == SignPhase::kPhase5,
             "Non-aborted peers should remain in phase5");
      Expect(session->phase5_stage() == SignPhase5Stage::kPhase5D ||
                 session->phase5_stage() == SignPhase5Stage::kPhase5E,
             "Non-aborted peers may stay at phase5D or wait in phase5E");
    }
    Expect(!session->HasResult(), "Failure path must not expose final signature");
  }
}

void TestM5Phase2InstanceIdMismatchAborts() {
  const auto keygen_results = RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xD3, 0x03, 0x01});
  const std::vector<PartyIndex> signers = {1, 2};
  const SignFixture fixture = BuildSignFixture(signers);
  auto sessions = BuildSignSessions(fixture, keygen_results, Bytes{0xE3, 0x02, 0x01});

  DeliverSignEnvelopesOrThrow(CollectPhase1Messages(&sessions), signers, &sessions);
  EnsureAllSessionsInPhase(sessions, SignPhase::kPhase2);

  DeliverSignEnvelopesOrThrow(CollectPhase2Messages(&sessions), signers, &sessions);

  std::vector<Envelope> phase2_round2 = CollectPhase2Messages(&sessions);
  bool tampered = false;
  for (Envelope& envelope : phase2_round2) {
    if (envelope.type == SignSession::Phase2ResponseMessageType() && envelope.payload.size() > 8) {
      envelope.payload[8] ^= 0x01;
      tampered = true;
      break;
    }
  }
  Expect(tampered, "Test setup failed to locate a phase2 response envelope to tamper");

  for (const Envelope& envelope : phase2_round2) {
    (void)DeliverSignEnvelope(envelope, signers, &sessions);
  }

  bool any_aborted = false;
  for (const auto& session : sessions) {
    if (session->status() == SessionStatus::kAborted) {
      any_aborted = true;
    }
    Expect(!session->HasResult(), "Phase2-aborted session must not expose final signature");
  }
  Expect(any_aborted, "At least one signer must abort on mismatched phase2 instance id");
}

void TestM7TamperedPhase2A1ProofAbortsResponder() {
  const auto keygen_results = RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xD7, 0x03, 0x01});
  const std::vector<PartyIndex> signers = {1, 2};
  const SignFixture fixture = BuildSignFixture(signers);
  auto sessions = BuildSignSessions(fixture, keygen_results, Bytes{0xE7, 0x02, 0x01});

  DeliverSignEnvelopesOrThrow(CollectPhase1Messages(&sessions), signers, &sessions);
  EnsureAllSessionsInPhase(sessions, SignPhase::kPhase2);

  std::vector<Envelope> phase2_init = CollectPhase2Messages(&sessions);
  bool tampered = false;
  for (Envelope& envelope : phase2_init) {
    if (envelope.type == SignSession::MessageTypeForPhase(SignPhase::kPhase2) &&
        envelope.from == 1 &&
        envelope.to == 2 &&
        !envelope.payload.empty()) {
      envelope.payload.back() ^= 0x01;
      tampered = true;
      break;
    }
  }
  Expect(tampered, "Test setup failed to locate phase2 init A1 proof payload to tamper");

  for (const Envelope& envelope : phase2_init) {
    (void)DeliverSignEnvelope(envelope, signers, &sessions);
  }

  const size_t receiver_idx = FindPartyIndexOrThrow(signers, 2);
  Expect(sessions[receiver_idx]->status() == SessionStatus::kAborted,
         "Responder must abort when phase2 A1 proof is tampered");
  for (const auto& session : sessions) {
    Expect(!session->HasResult(), "Phase2 A1 proof failure must not expose signature");
  }
}

void TestM7TamperedPhase2A3ProofAbortsInitiator() {
  const auto keygen_results = RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xD8, 0x03, 0x01});
  const std::vector<PartyIndex> signers = {1, 2};
  const SignFixture fixture = BuildSignFixture(signers);
  auto sessions = BuildSignSessions(fixture, keygen_results, Bytes{0xE8, 0x02, 0x01});

  DeliverSignEnvelopesOrThrow(CollectPhase1Messages(&sessions), signers, &sessions);
  EnsureAllSessionsInPhase(sessions, SignPhase::kPhase2);
  DeliverSignEnvelopesOrThrow(CollectPhase2Messages(&sessions), signers, &sessions);

  std::vector<Envelope> phase2_responses = CollectPhase2Messages(&sessions);
  bool tampered = false;
  for (Envelope& envelope : phase2_responses) {
    if (envelope.type != SignSession::Phase2ResponseMessageType() ||
        envelope.from != 2 ||
        envelope.to != 1 ||
        envelope.payload.size() < 4) {
      continue;
    }
    const uint32_t raw_type = ReadU32Be(envelope.payload, 0);
    if (raw_type != 1) {  // MtA (times-gamma) uses A3
      continue;
    }
    envelope.payload.back() ^= 0x01;
    tampered = true;
    break;
  }
  Expect(tampered, "Test setup failed to locate phase2 response A3 proof payload to tamper");

  for (const Envelope& envelope : phase2_responses) {
    (void)DeliverSignEnvelope(envelope, signers, &sessions);
  }

  const size_t initiator_idx = FindPartyIndexOrThrow(signers, 1);
  Expect(sessions[initiator_idx]->status() == SessionStatus::kAborted,
         "Initiator must abort when phase2 A3 proof is tampered");
  for (const auto& session : sessions) {
    Expect(!session->HasResult(), "Phase2 A3 proof failure must not expose signature");
  }
}

void TestM7TamperedPhase2A2ProofAbortsInitiator() {
  const auto keygen_results = RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xD9, 0x03, 0x01});
  const std::vector<PartyIndex> signers = {1, 2};
  const SignFixture fixture = BuildSignFixture(signers);
  auto sessions = BuildSignSessions(fixture, keygen_results, Bytes{0xE9, 0x02, 0x01});

  DeliverSignEnvelopesOrThrow(CollectPhase1Messages(&sessions), signers, &sessions);
  EnsureAllSessionsInPhase(sessions, SignPhase::kPhase2);
  DeliverSignEnvelopesOrThrow(CollectPhase2Messages(&sessions), signers, &sessions);

  std::vector<Envelope> phase2_responses = CollectPhase2Messages(&sessions);
  bool tampered = false;
  for (Envelope& envelope : phase2_responses) {
    if (envelope.type != SignSession::Phase2ResponseMessageType() ||
        envelope.from != 2 ||
        envelope.to != 1 ||
        envelope.payload.size() < 4) {
      continue;
    }
    const uint32_t raw_type = ReadU32Be(envelope.payload, 0);
    if (raw_type != 2) {  // MtAwc (times-w) uses A2
      continue;
    }
    envelope.payload.back() ^= 0x01;
    tampered = true;
    break;
  }
  Expect(tampered, "Test setup failed to locate phase2 response A2 proof payload to tamper");

  for (const Envelope& envelope : phase2_responses) {
    (void)DeliverSignEnvelope(envelope, signers, &sessions);
  }

  const size_t initiator_idx = FindPartyIndexOrThrow(signers, 1);
  Expect(sessions[initiator_idx]->status() == SessionStatus::kAborted,
         "Initiator must abort when phase2 A2 proof is tampered");
  for (const auto& session : sessions) {
    Expect(!session->HasResult(), "Phase2 A2 proof failure must not expose signature");
  }
}

void TestM6TamperedPhase4GammaSchnorrAbortsReceiver() {
  const auto keygen_results = RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xD4, 0x03, 0x01});
  const std::vector<PartyIndex> signers = {1, 2};
  const SignFixture fixture = BuildSignFixture(signers);
  auto sessions = BuildSignSessions(fixture, keygen_results, Bytes{0xE4, 0x02, 0x01});

  DeliverSignEnvelopesOrThrow(CollectPhase1Messages(&sessions), signers, &sessions);
  EnsureAllSessionsInPhase(sessions, SignPhase::kPhase2);

  for (size_t round = 0; round < 32; ++round) {
    const std::vector<Envelope> phase2_messages = CollectPhase2Messages(&sessions);
    if (phase2_messages.empty()) {
      throw std::runtime_error("phase2 stalled before MtA/MtAwc completion");
    }
    DeliverSignEnvelopesOrThrow(phase2_messages, signers, &sessions);

    bool all_phase3 = true;
    for (const auto& session : sessions) {
      if (session->phase() != SignPhase::kPhase3) {
        all_phase3 = false;
        break;
      }
    }
    if (all_phase3) {
      break;
    }
  }
  EnsureAllSessionsInPhase(sessions, SignPhase::kPhase3);

  DeliverSignEnvelopesOrThrow(CollectPhase3Messages(&sessions), signers, &sessions);
  EnsureAllSessionsInPhase(sessions, SignPhase::kPhase4);

  std::vector<Envelope> phase4_messages = CollectPhase4Messages(&sessions);
  bool tampered = false;
  for (Envelope& envelope : phase4_messages) {
    if (envelope.from == 1 && !envelope.payload.empty()) {
      envelope.payload.back() ^= 0x01;
      tampered = true;
      break;
    }
  }
  Expect(tampered, "Test setup failed to locate phase4 proof payload to tamper");

  for (const Envelope& envelope : phase4_messages) {
    (void)DeliverSignEnvelope(envelope, signers, &sessions);
  }

  const size_t receiver_idx = FindPartyIndexOrThrow(signers, 2);
  Expect(sessions[receiver_idx]->status() == SessionStatus::kAborted,
         "Receiver must abort when phase4 gamma Schnorr proof is tampered");
  Expect(sessions[receiver_idx]->phase() == SignPhase::kPhase4,
         "Phase4 proof failure should abort in phase4");
  for (const auto& session : sessions) {
    Expect(!session->HasResult(), "Phase4 proof failure must not expose signature result");
  }
}

void TestM6TamperedPhase5BASchnorrAbortsReceiver() {
  const auto keygen_results = RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xD5, 0x03, 0x01});
  const std::vector<PartyIndex> signers = {1, 2};
  const SignFixture fixture = BuildSignFixture(signers);
  auto sessions = BuildSignSessions(fixture, keygen_results, Bytes{0xE5, 0x02, 0x01});

  RunToPhase5B(&sessions, signers);

  std::vector<Envelope> phase5b_messages = CollectPhase5BMessages(&sessions);
  bool tampered = false;
  for (Envelope& envelope : phase5b_messages) {
    if (envelope.from == 1) {
      tampered = TamperPhase5BSchnorrProof(&envelope);
      if (tampered) {
        break;
      }
    }
  }
  Expect(tampered, "Test setup failed to locate phase5B Schnorr proof payload to tamper");

  for (const Envelope& envelope : phase5b_messages) {
    (void)DeliverSignEnvelope(envelope, signers, &sessions);
  }

  const size_t receiver_idx = FindPartyIndexOrThrow(signers, 2);
  Expect(sessions[receiver_idx]->status() == SessionStatus::kAborted,
         "Receiver must abort when phase5B A_i Schnorr proof is tampered");
  Expect(sessions[receiver_idx]->phase() == SignPhase::kPhase5,
         "Phase5B proof failure should abort in phase5");
  Expect(sessions[receiver_idx]->phase5_stage() == SignPhase5Stage::kPhase5B,
         "Phase5B A_i proof failure should abort in stage5B");
  for (const auto& session : sessions) {
    Expect(!session->HasResult(), "Phase5B Schnorr proof failure must not expose signature result");
  }
}

void TestM6TamperedPhase5BVRelationAbortsReceiver() {
  const auto keygen_results = RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xD6, 0x03, 0x01});
  const std::vector<PartyIndex> signers = {1, 2};
  const SignFixture fixture = BuildSignFixture(signers);
  auto sessions = BuildSignSessions(fixture, keygen_results, Bytes{0xE6, 0x02, 0x01});

  RunToPhase5B(&sessions, signers);

  std::vector<Envelope> phase5b_messages = CollectPhase5BMessages(&sessions);
  bool tampered = false;
  for (Envelope& envelope : phase5b_messages) {
    if (envelope.from == 1 && !envelope.payload.empty()) {
      envelope.payload.back() ^= 0x01;
      tampered = true;
      break;
    }
  }
  Expect(tampered, "Test setup failed to locate phase5B relation proof payload to tamper");

  for (const Envelope& envelope : phase5b_messages) {
    (void)DeliverSignEnvelope(envelope, signers, &sessions);
  }

  const size_t receiver_idx = FindPartyIndexOrThrow(signers, 2);
  Expect(sessions[receiver_idx]->status() == SessionStatus::kAborted,
         "Receiver must abort when phase5B V relation proof is tampered");
  Expect(sessions[receiver_idx]->phase() == SignPhase::kPhase5,
         "Phase5B proof failure should abort in phase5");
  Expect(sessions[receiver_idx]->phase5_stage() == SignPhase5Stage::kPhase5B,
         "Phase5B relation proof failure should abort in stage5B");
  for (const auto& session : sessions) {
    Expect(!session->HasResult(), "Phase5B relation proof failure must not expose signature result");
  }
}

void TestM9TamperedPhase4GammaPointAbortsReceiver() {
  const auto keygen_results = RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xDA, 0x03, 0x01});
  const std::vector<PartyIndex> signers = {1, 2};
  const SignFixture fixture = BuildSignFixture(signers);
  auto sessions = BuildSignSessions(fixture, keygen_results, Bytes{0xEA, 0x02, 0x01});

  RunToPhase4(&sessions, signers);

  std::vector<Envelope> phase4_messages = CollectPhase4Messages(&sessions);
  Bytes replacement_gamma;
  for (const Envelope& envelope : phase4_messages) {
    if (envelope.from == 2 && envelope.payload.size() >= 33) {
      replacement_gamma.assign(envelope.payload.begin(), envelope.payload.begin() + 33);
      break;
    }
  }
  Expect(!replacement_gamma.empty(), "Test setup failed to capture replacement Gamma_i point");

  bool tampered = false;
  for (Envelope& envelope : phase4_messages) {
    if (envelope.from == 1) {
      tampered = ReplacePhase4GammaPoint(&envelope, replacement_gamma);
      if (tampered) {
        break;
      }
    }
  }
  Expect(tampered, "Test setup failed to locate phase4 Gamma_i payload to tamper");

  for (const Envelope& envelope : phase4_messages) {
    (void)DeliverSignEnvelope(envelope, signers, &sessions);
  }

  const size_t receiver_idx = FindPartyIndexOrThrow(signers, 2);
  Expect(sessions[receiver_idx]->status() == SessionStatus::kAborted,
         "Receiver must abort when phase4 Gamma_i is inconsistent");
  for (const auto& session : sessions) {
    Expect(!session->HasResult(), "Tampered Gamma_i path must not expose signature result");
  }
}

void TestM9TamperedPhase5ACommitmentAbortsReceiver() {
  const auto keygen_results = RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xDB, 0x03, 0x01});
  const std::vector<PartyIndex> signers = {1, 2};
  const SignFixture fixture = BuildSignFixture(signers);
  auto sessions = BuildSignSessions(fixture, keygen_results, Bytes{0xEB, 0x02, 0x01});

  RunToPhase5A(&sessions, signers);

  std::vector<Envelope> phase5a_messages = CollectPhase5AMessages(&sessions);
  bool tampered = false;
  for (Envelope& envelope : phase5a_messages) {
    if (envelope.from == 1 && !envelope.payload.empty()) {
      envelope.payload[0] ^= 0x01;
      tampered = true;
      break;
    }
  }
  Expect(tampered, "Test setup failed to locate phase5A commitment payload to tamper");

  DeliverSignEnvelopesOrThrow(phase5a_messages, signers, &sessions);
  EnsureAllSessionsInPhase(sessions, SignPhase::kPhase5, SignPhase5Stage::kPhase5B);

  for (const Envelope& envelope : CollectPhase5BMessages(&sessions)) {
    (void)DeliverSignEnvelope(envelope, signers, &sessions);
  }

  const size_t receiver_idx = FindPartyIndexOrThrow(signers, 2);
  Expect(sessions[receiver_idx]->status() == SessionStatus::kAborted,
         "Receiver must abort when phase5A commitment is tampered");
  for (const auto& session : sessions) {
    Expect(!session->HasResult(), "Tampered phase5A commitment path must not expose signature result");
  }
}

void TestM9TamperedPhase3DeltaShareAbortsAndNoResult() {
  const auto keygen_results = RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xDC, 0x03, 0x01});
  const std::vector<PartyIndex> signers = {1, 2};
  const SignFixture fixture = BuildSignFixture(signers);
  auto sessions = BuildSignSessions(fixture, keygen_results, Bytes{0xEC, 0x02, 0x01});

  DeliverSignEnvelopesOrThrow(CollectPhase1Messages(&sessions), signers, &sessions);
  EnsureAllSessionsInPhase(sessions, SignPhase::kPhase2);

  for (size_t round = 0; round < 32; ++round) {
    const std::vector<Envelope> phase2_messages = CollectPhase2Messages(&sessions);
    if (phase2_messages.empty()) {
      throw std::runtime_error("phase2 stalled before MtA/MtAwc completion");
    }
    DeliverSignEnvelopesOrThrow(phase2_messages, signers, &sessions);

    bool all_phase3 = true;
    for (const auto& session : sessions) {
      if (session->phase() != SignPhase::kPhase3) {
        all_phase3 = false;
        break;
      }
    }
    if (all_phase3) {
      break;
    }
  }
  EnsureAllSessionsInPhase(sessions, SignPhase::kPhase3);

  std::vector<Envelope> phase3_messages = CollectPhase3Messages(&sessions);
  bool tampered = false;
  for (Envelope& envelope : phase3_messages) {
    if (envelope.from != 1 || envelope.payload.size() != 32) {
      continue;
    }
    const Scalar parsed = Scalar::FromCanonicalBytes(envelope.payload);
    const Scalar tampered_delta = parsed + Scalar::FromUint64(1);
    const auto encoded = tampered_delta.ToCanonicalBytes();
    envelope.payload.assign(encoded.begin(), encoded.end());
    tampered = true;
    break;
  }
  Expect(tampered, "Test setup failed to locate phase3 delta share to tamper");

  for (const Envelope& envelope : phase3_messages) {
    (void)DeliverSignEnvelope(envelope, signers, &sessions);
  }

  try {
    EnsureAllSessionsInPhase(sessions, SignPhase::kPhase4);
    DeliverSignEnvelopesOrThrow(CollectPhase4Messages(&sessions), signers, &sessions);
    EnsureAllSessionsInPhase(sessions, SignPhase::kPhase5, SignPhase5Stage::kPhase5A);
    DeliverSignEnvelopesOrThrow(CollectPhase5AMessages(&sessions), signers, &sessions);
    EnsureAllSessionsInPhase(sessions, SignPhase::kPhase5, SignPhase5Stage::kPhase5B);
    DeliverSignEnvelopesOrThrow(CollectPhase5BMessages(&sessions), signers, &sessions);
  } catch (const std::exception&) {
    // Failure during adversarial progression is expected.
  }

  bool any_aborted = false;
  for (const auto& session : sessions) {
    if (session->status() == SessionStatus::kAborted) {
      any_aborted = true;
    }
    Expect(!session->HasResult(), "Tampered delta path must not expose signature result");
  }
  Expect(any_aborted, "At least one party must abort when phase3 delta share is tampered");
}

void TestM9TamperedPhase5BVPointAbortsReceiver() {
  const auto keygen_results = RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xDD, 0x03, 0x01});
  const std::vector<PartyIndex> signers = {1, 2};
  const SignFixture fixture = BuildSignFixture(signers);
  auto sessions = BuildSignSessions(fixture, keygen_results, Bytes{0xED, 0x02, 0x01});

  RunToPhase5B(&sessions, signers);

  std::vector<Envelope> phase5b_messages = CollectPhase5BMessages(&sessions);
  Bytes replacement_v;
  for (const Envelope& envelope : phase5b_messages) {
    if (envelope.from == 2 && envelope.payload.size() >= 33) {
      replacement_v.assign(envelope.payload.begin(), envelope.payload.begin() + 33);
      break;
    }
  }
  Expect(!replacement_v.empty(), "Test setup failed to capture replacement V_i point");

  bool tampered = false;
  for (Envelope& envelope : phase5b_messages) {
    if (envelope.from == 1) {
      tampered = ReplacePhase5BVPoint(&envelope, replacement_v);
      if (tampered) {
        break;
      }
    }
  }
  Expect(tampered, "Test setup failed to locate phase5B V_i payload to tamper");

  for (const Envelope& envelope : phase5b_messages) {
    (void)DeliverSignEnvelope(envelope, signers, &sessions);
  }

  const size_t receiver_idx = FindPartyIndexOrThrow(signers, 2);
  Expect(sessions[receiver_idx]->status() == SessionStatus::kAborted,
         "Receiver must abort when phase5B V_i is tampered");
  for (const auto& session : sessions) {
    Expect(!session->HasResult(), "Tampered V_i path must not expose signature result");
  }
}

}  // namespace tecdsa::sign_flow_test
