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

#include "sign_flow_test_shared.h"

#include "yacl/crypto/experimental/threshold_ecdsa/crypto/ecdsa_verify.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/strict_proofs.h"

namespace tecdsa::sign_flow_test {
namespace {

struct SignRoundState {
  PeerMap<SignRound1Msg> round1;
  std::vector<SignRound2Request> round2_requests;
  std::vector<SignRound2Response> round2_responses;
  PeerMap<SignRound3Msg> round3;
  PeerMap<SignRound4Msg> round4;
  PeerMap<SignRound5AMsg> round5a;
  PeerMap<SignRound5BMsg> round5b;
  PeerMap<SignRound5CMsg> round5c;
  PeerMap<SignRound5DMsg> round5d;
  PeerMap<Scalar> round5e;
};

SignPartyMap BuildDefaultSignParties(const KeygenOutputs& keygen_results,
                                     const Bytes& keygen_session_id,
                                     const Bytes& sign_session_id) {
  const std::vector<PartyIndex> signers = {1, 2};
  const SignFixture fixture = BuildSignFixture(signers);
  return BuildSignParties(fixture, keygen_results, sign_session_id,
                          keygen_session_id);
}

void RunToRound4(SignPartyMap* parties, const std::vector<PartyIndex>& signers,
                 SignRoundState* state) {
  state->round1 = CollectRound1Messages(parties, signers);
  state->round2_requests =
      CollectRound2Requests(parties, signers, state->round1);
  state->round2_responses =
      CollectRound2Responses(parties, signers, state->round2_requests);
  state->round3 =
      CollectRound3Messages(parties, signers, state->round2_responses);
  state->round4 = CollectRound4Messages(parties, signers, state->round3);
}

void RunToRound3(SignPartyMap* parties, const std::vector<PartyIndex>& signers,
                 SignRoundState* state) {
  state->round1 = CollectRound1Messages(parties, signers);
  state->round2_requests =
      CollectRound2Requests(parties, signers, state->round1);
  state->round2_responses =
      CollectRound2Responses(parties, signers, state->round2_requests);
  state->round3 =
      CollectRound3Messages(parties, signers, state->round2_responses);
}

void RunToRound5A(SignPartyMap* parties, const std::vector<PartyIndex>& signers,
                  SignRoundState* state) {
  RunToRound4(parties, signers, state);
  state->round5a = CollectRound5AMessages(parties, signers, state->round4);
}

void RunToRound5B(SignPartyMap* parties, const std::vector<PartyIndex>& signers,
                  SignRoundState* state) {
  RunToRound5A(parties, signers, state);
  state->round5b = CollectRound5BMessages(parties, signers, state->round5a);
}

void RunToRound5D(SignPartyMap* parties, const std::vector<PartyIndex>& signers,
                  SignRoundState* state) {
  RunToRound5B(parties, signers, state);
  state->round5c = CollectRound5CMessages(parties, signers, state->round5b);
  state->round5d = CollectRound5DMessages(parties, signers, state->round5c);
}

void RunToCompletion(SignPartyMap* parties,
                     const std::vector<PartyIndex>& signers,
                     SignRoundState* state) {
  RunToRound5D(parties, signers, state);
  state->round5e = CollectRound5EReveals(parties, signers, state->round5d);
}

}  // namespace

void TestStage4SignConstructorRejectsSmallPaillierModulus() {
  const auto keygen_results =
      RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xD0, 0x03, 0x02});
  const std::vector<PartyIndex> signers = {1, 2};
  const SignFixture fixture = BuildSignFixture(signers);
  std::vector<SignConfig> configs =
      BuildSignConfigs(fixture, keygen_results, Bytes{0xE0, 0x02, 0x02},
                       Bytes{0xD0, 0x03, 0x02});

  const size_t cfg_idx = FindPartyIndexOrThrow(signers, 1);
  SignConfig bad_cfg = std::move(configs[cfg_idx]);
  bad_cfg.public_keygen_data.all_paillier_public.at(2).n = tecdsa::BigInt(17);

  ExpectThrow([&]() { (void)SignParty(std::move(bad_cfg)); },
              "SignParty must reject participant Paillier modulus N <= q^8");
}

void TestStage6SignConstructorRejectsMissingKeygenProofArtifacts() {
  const auto keygen_results =
      RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xDE, 0x03, 0x01});
  const std::vector<PartyIndex> signers = {1, 2};
  const SignFixture fixture = BuildSignFixture(signers);
  std::vector<SignConfig> configs =
      BuildSignConfigs(fixture, keygen_results, Bytes{0xEE, 0x02, 0x01},
                       Bytes{0xDE, 0x03, 0x01});

  const size_t cfg_idx = FindPartyIndexOrThrow(signers, 1);
  SignConfig missing_cfg = configs[cfg_idx];
  missing_cfg.public_keygen_data.all_square_free_proofs.clear();
  missing_cfg.public_keygen_data.all_aux_param_proofs.clear();

  ExpectThrow([&]() { (void)SignParty(std::move(missing_cfg)); },
              "SignParty must reject missing keygen proof artifacts");
}

void TestStage6SignConstructorRejectsInvalidKeygenProofArtifacts() {
  const auto keygen_results =
      RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xDF, 0x03, 0x01});
  const std::vector<PartyIndex> signers = {1, 2};
  const SignFixture fixture = BuildSignFixture(signers);
  std::vector<SignConfig> configs =
      BuildSignConfigs(fixture, keygen_results, Bytes{0xEF, 0x02, 0x01},
                       Bytes{0xDF, 0x03, 0x01});

  const size_t cfg_idx = FindPartyIndexOrThrow(signers, 1);

  SignConfig bad_square_cfg = configs[cfg_idx];
  bad_square_cfg.public_keygen_data.all_square_free_proofs.at(2).blob.back() ^=
      0x01;
  ExpectThrow([&]() { (void)SignParty(std::move(bad_square_cfg)); },
              "SignParty must reject invalid square-free keygen proof");

  SignConfig bad_aux_cfg = configs[cfg_idx];
  bad_aux_cfg.public_keygen_data.all_aux_param_proofs.at(2).blob.back() ^= 0x01;
  ExpectThrow([&]() { (void)SignParty(std::move(bad_aux_cfg)); },
              "SignParty must reject invalid aux keygen proof");
}

void TestStage6MalformedPhase2InitProofPayloadAbortsResponder() {
  const auto keygen_results =
      RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xE0, 0x03, 0x01});
  const std::vector<PartyIndex> signers = {1, 2};
  auto parties = BuildDefaultSignParties(
      keygen_results, Bytes{0xE0, 0x03, 0x01}, Bytes{0xF0, 0x02, 0x01});

  const auto round1 = CollectRound1Messages(&parties, signers);
  std::vector<SignRound2Request> round2_requests =
      CollectRound2Requests(&parties, signers, round1);
  bool tampered = false;
  for (SignRound2Request& request : round2_requests) {
    if (request.from == 1 && request.to == 2) {
      request.instance_id.clear();
      tampered = true;
      break;
    }
  }
  Expect(tampered, "test setup failed to locate round2 request to truncate");

  ExpectThrow(
      [&]() {
        (void)CollectRound2Responses(&parties, signers, round2_requests);
      },
      "Responder must reject malformed round2 request instance id");
}

void TestStage6MalformedPhase2ResponseProofPayloadAbortsInitiator() {
  const auto keygen_results =
      RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xE1, 0x03, 0x01});
  const std::vector<PartyIndex> signers = {1, 2};
  auto parties = BuildDefaultSignParties(
      keygen_results, Bytes{0xE1, 0x03, 0x01}, Bytes{0xF1, 0x02, 0x01});

  const auto round1 = CollectRound1Messages(&parties, signers);
  const auto round2_requests = CollectRound2Requests(&parties, signers, round1);
  std::vector<SignRound2Response> round2_responses =
      CollectRound2Responses(&parties, signers, round2_requests);
  bool tampered = false;
  for (SignRound2Response& response : round2_responses) {
    if (response.from == 2 && response.to == 1) {
      response.instance_id.clear();
      tampered = true;
      break;
    }
  }
  Expect(tampered, "test setup failed to locate round2 response to truncate");

  ExpectThrow(
      [&]() {
        (void)CollectRound3Messages(&parties, signers, round2_responses);
      },
      "Initiator must reject malformed round2 response instance id");
}

void TestStage4Phase2InitUsesResponderOwnedAuxParams() {
  const auto keygen_results =
      RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xD0, 0x03, 0x03});
  const std::vector<PartyIndex> signers = {1, 2};
  const SignFixture fixture = BuildSignFixture(signers);
  std::vector<SignConfig> configs =
      BuildSignConfigs(fixture, keygen_results, Bytes{0xE0, 0x02, 0x03},
                       Bytes{0xD0, 0x03, 0x03});

  const size_t responder_idx = FindPartyIndexOrThrow(signers, 2);
  SignConfig& responder_cfg = configs[responder_idx];
  const auto initiator_aux_it =
      responder_cfg.public_keygen_data.all_aux_rsa_params.find(1);
  Expect(initiator_aux_it !=
             responder_cfg.public_keygen_data.all_aux_rsa_params.end(),
         "responder config must include initiator aux params");
  responder_cfg.public_keygen_data.all_aux_rsa_params[2] =
      initiator_aux_it->second;
  responder_cfg.public_keygen_data.all_aux_param_proofs[2] =
      tecdsa::BuildAuxRsaParamProofStrict(
          initiator_aux_it->second,
          BuildKeygenProofContext(responder_cfg.keygen_session_id,
                                  /*prover_id=*/2));

  SignPartyMap parties;
  for (SignConfig& cfg : configs) {
    parties.emplace(cfg.self_id, SignParty(std::move(cfg)));
  }

  const auto round1 = CollectRound1Messages(&parties, signers);
  const auto round2_requests = CollectRound2Requests(&parties, signers, round1);
  ExpectThrow(
      [&]() {
        (void)CollectRound2Responses(&parties, signers, round2_requests);
      },
      "Responder must reject A1 verification under wrong aux params");
}

void TestStage4Phase2ResponseUsesInitiatorOwnedAuxParams() {
  const auto keygen_results =
      RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xD0, 0x03, 0x04});
  const std::vector<PartyIndex> signers = {1, 2};
  const SignFixture fixture = BuildSignFixture(signers);
  std::vector<SignConfig> configs =
      BuildSignConfigs(fixture, keygen_results, Bytes{0xE0, 0x02, 0x04},
                       Bytes{0xD0, 0x03, 0x04});

  const size_t responder_idx = FindPartyIndexOrThrow(signers, 2);
  SignConfig& responder_cfg = configs[responder_idx];
  const auto self_aux_it =
      responder_cfg.public_keygen_data.all_aux_rsa_params.find(2);
  Expect(
      self_aux_it != responder_cfg.public_keygen_data.all_aux_rsa_params.end(),
      "responder config must include self aux params");
  responder_cfg.public_keygen_data.all_aux_rsa_params[1] = self_aux_it->second;
  responder_cfg.public_keygen_data.all_aux_param_proofs[1] =
      tecdsa::BuildAuxRsaParamProofStrict(
          self_aux_it->second,
          BuildKeygenProofContext(responder_cfg.keygen_session_id,
                                  /*prover_id=*/1));

  SignPartyMap parties;
  for (SignConfig& cfg : configs) {
    parties.emplace(cfg.self_id, SignParty(std::move(cfg)));
  }

  const auto round1 = CollectRound1Messages(&parties, signers);
  const auto round2_requests = CollectRound2Requests(&parties, signers, round1);
  std::vector<SignRound2Request> requests_for_responder;
  for (const SignRound2Request& request : round2_requests) {
    if (request.from == 1 && request.to == 2) {
      requests_for_responder.push_back(request);
    }
  }
  Expect(requests_for_responder.size() == 2,
         "expected two round2 requests from initiator to responder");

  const std::vector<SignRound2Response> responder_responses =
      parties.at(2).MakeRound2Responses(requests_for_responder);
  ExpectThrow(
      [&]() { (void)parties.at(1).MakeRound3(responder_responses); },
      "Initiator must reject A2/A3 verification under wrong aux params");
}

void TestM4SignEndToEndProducesVerifiableSignature() {
  const auto keygen_results =
      RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xD1, 0x03, 0x01});
  const std::vector<PartyIndex> signers = {1, 2};
  const SignFixture fixture = BuildSignFixture(signers);
  auto parties =
      BuildSignParties(fixture, keygen_results, Bytes{0xE1, 0x02, 0x01},
                       Bytes{0xD1, 0x03, 0x01});

  SignRoundState state;
  RunToCompletion(&parties, signers, &state);
  const auto signatures = FinalizeSignatures(&parties, signers, state.round5e);

  const Signature& baseline = signatures.at(signers.front());
  Expect(baseline.r.value() != 0, "final signature r must be non-zero");
  Expect(baseline.s.value() != 0, "final signature s must be non-zero");
  Expect(tecdsa::VerifyEcdsaSignatureMath(
             keygen_results.at(1).public_keygen_data.y, fixture.msg32,
             baseline.r, baseline.s),
         "final signature must verify");

  for (PartyIndex signer : signers) {
    const Signature& signature = signatures.at(signer);
    Expect(signature.r == baseline.r, "all signers must derive same r");
    Expect(signature.s == baseline.s, "all signers must derive same s");
    Expect(signature.R == baseline.R, "all signers must derive same R");
  }
}

void TestM4Phase5DFailurePreventsPhase5EReveal() {
  const auto keygen_results =
      RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xD2, 0x03, 0x01});
  const std::vector<PartyIndex> signers = {1, 2};
  auto parties = BuildDefaultSignParties(
      keygen_results, Bytes{0xD2, 0x03, 0x01}, Bytes{0xE2, 0x02, 0x01});

  SignRoundState state;
  RunToRound5D(&parties, signers, &state);
  state.round5d.at(1).randomness.push_back(0x01);

  ExpectThrow(
      [&]() {
        PeerMap<SignRound5DMsg> peer_round5d;
        peer_round5d.emplace(1, state.round5d.at(1));
        (void)parties.at(2).RevealRound5E(peer_round5d);
      },
      "RevealRound5E must fail when phase5D opening is tampered");
}

void TestM5Phase2InstanceIdMismatchAborts() {
  const auto keygen_results =
      RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xD3, 0x03, 0x01});
  const std::vector<PartyIndex> signers = {1, 2};
  auto parties = BuildDefaultSignParties(
      keygen_results, Bytes{0xD3, 0x03, 0x01}, Bytes{0xE3, 0x02, 0x01});

  const auto round1 = CollectRound1Messages(&parties, signers);
  const auto round2_requests = CollectRound2Requests(&parties, signers, round1);
  std::vector<SignRound2Response> round2_responses =
      CollectRound2Responses(&parties, signers, round2_requests);
  bool tampered = false;
  for (SignRound2Response& response : round2_responses) {
    if (response.from == 2 && response.to == 1 &&
        !response.instance_id.empty()) {
      response.instance_id[0] ^= 0x01;
      tampered = true;
      break;
    }
  }
  Expect(tampered, "test setup failed to locate round2 response instance id");

  ExpectThrow(
      [&]() {
        (void)CollectRound3Messages(&parties, signers, round2_responses);
      },
      "signer must reject mismatched round2 instance id");
}

void TestM7TamperedPhase2A1ProofAbortsResponder() {
  const auto keygen_results =
      RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xD7, 0x03, 0x01});
  const std::vector<PartyIndex> signers = {1, 2};
  auto parties = BuildDefaultSignParties(
      keygen_results, Bytes{0xD7, 0x03, 0x01}, Bytes{0xE7, 0x02, 0x01});

  const auto round1 = CollectRound1Messages(&parties, signers);
  std::vector<SignRound2Request> round2_requests =
      CollectRound2Requests(&parties, signers, round1);
  bool tampered = false;
  for (SignRound2Request& request : round2_requests) {
    if (request.from == 1 && request.to == 2) {
      request.a1_proof.s2 += tecdsa::BigInt(1);
      tampered = true;
      break;
    }
  }
  Expect(tampered, "test setup failed to locate round2 A1 proof to tamper");

  ExpectThrow(
      [&]() {
        (void)CollectRound2Responses(&parties, signers, round2_requests);
      },
      "responder must reject tampered A1 proof");
}

void TestM7TamperedPhase2A3ProofAbortsInitiator() {
  const auto keygen_results =
      RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xD8, 0x03, 0x01});
  const std::vector<PartyIndex> signers = {1, 2};
  auto parties = BuildDefaultSignParties(
      keygen_results, Bytes{0xD8, 0x03, 0x01}, Bytes{0xE8, 0x02, 0x01});

  const auto round1 = CollectRound1Messages(&parties, signers);
  const auto round2_requests = CollectRound2Requests(&parties, signers, round1);
  std::vector<SignRound2Response> round2_responses =
      CollectRound2Responses(&parties, signers, round2_requests);
  bool tampered = false;
  for (SignRound2Response& response : round2_responses) {
    if (response.from == 2 && response.to == 1 &&
        response.type == tecdsa::proto::MtaType::kTimesGamma &&
        response.a3_proof.has_value()) {
      response.a3_proof->t2 += tecdsa::BigInt(1);
      tampered = true;
      break;
    }
  }
  Expect(tampered, "test setup failed to locate round2 A3 proof to tamper");

  ExpectThrow(
      [&]() {
        (void)CollectRound3Messages(&parties, signers, round2_responses);
      },
      "initiator must reject tampered A3 proof");
}

void TestM7TamperedPhase2A2ProofAbortsInitiator() {
  const auto keygen_results =
      RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xD9, 0x03, 0x01});
  const std::vector<PartyIndex> signers = {1, 2};
  auto parties = BuildDefaultSignParties(
      keygen_results, Bytes{0xD9, 0x03, 0x01}, Bytes{0xE9, 0x02, 0x01});

  const auto round1 = CollectRound1Messages(&parties, signers);
  const auto round2_requests = CollectRound2Requests(&parties, signers, round1);
  std::vector<SignRound2Response> round2_responses =
      CollectRound2Responses(&parties, signers, round2_requests);
  bool tampered = false;
  for (SignRound2Response& response : round2_responses) {
    if (response.from == 2 && response.to == 1 &&
        response.type == tecdsa::proto::MtaType::kTimesW &&
        response.a2_proof.has_value()) {
      response.a2_proof->t2 += tecdsa::BigInt(1);
      tampered = true;
      break;
    }
  }
  Expect(tampered, "test setup failed to locate round2 A2 proof to tamper");

  ExpectThrow(
      [&]() {
        (void)CollectRound3Messages(&parties, signers, round2_responses);
      },
      "initiator must reject tampered A2 proof");
}

void TestM6TamperedPhase4GammaSchnorrAbortsReceiver() {
  const auto keygen_results =
      RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xD4, 0x03, 0x01});
  const std::vector<PartyIndex> signers = {1, 2};
  auto parties = BuildDefaultSignParties(
      keygen_results, Bytes{0xD4, 0x03, 0x01}, Bytes{0xE4, 0x02, 0x01});

  SignRoundState state;
  RunToRound4(&parties, signers, &state);
  state.round4.at(1).gamma_proof.z =
      state.round4.at(1).gamma_proof.z + Scalar::FromUint64(1);

  ExpectThrow(
      [&]() { (void)CollectRound5AMessages(&parties, signers, state.round4); },
      "receiver must reject tampered round4 gamma Schnorr proof");
}

void TestM6TamperedPhase5BASchnorrAbortsReceiver() {
  const auto keygen_results =
      RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xD5, 0x03, 0x01});
  const std::vector<PartyIndex> signers = {1, 2};
  auto parties = BuildDefaultSignParties(
      keygen_results, Bytes{0xD5, 0x03, 0x01}, Bytes{0xE5, 0x02, 0x01});

  SignRoundState state;
  RunToRound5B(&parties, signers, &state);
  state.round5b.at(1).a_schnorr_proof.z =
      state.round5b.at(1).a_schnorr_proof.z + Scalar::FromUint64(1);

  ExpectThrow(
      [&]() { (void)CollectRound5CMessages(&parties, signers, state.round5b); },
      "receiver must reject tampered round5B A_i Schnorr proof");
}

void TestM6TamperedPhase5BVRelationAbortsReceiver() {
  const auto keygen_results =
      RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xD6, 0x03, 0x01});
  const std::vector<PartyIndex> signers = {1, 2};
  auto parties = BuildDefaultSignParties(
      keygen_results, Bytes{0xD6, 0x03, 0x01}, Bytes{0xE6, 0x02, 0x01});

  SignRoundState state;
  RunToRound5B(&parties, signers, &state);
  state.round5b.at(1).v_relation_proof.u =
      state.round5b.at(1).v_relation_proof.u + Scalar::FromUint64(1);

  ExpectThrow(
      [&]() { (void)CollectRound5CMessages(&parties, signers, state.round5b); },
      "receiver must reject tampered round5B V relation proof");
}

void TestM9TamperedPhase4GammaPointAbortsReceiver() {
  const auto keygen_results =
      RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xDA, 0x03, 0x01});
  const std::vector<PartyIndex> signers = {1, 2};
  auto parties = BuildDefaultSignParties(
      keygen_results, Bytes{0xDA, 0x03, 0x01}, Bytes{0xEA, 0x02, 0x01});

  SignRoundState state;
  RunToRound4(&parties, signers, &state);
  state.round4.at(1).gamma_i = state.round4.at(2).gamma_i;

  ExpectThrow(
      [&]() { (void)CollectRound5AMessages(&parties, signers, state.round4); },
      "receiver must reject inconsistent round4 Gamma_i");
}

void TestM9TamperedPhase5ACommitmentAbortsReceiver() {
  const auto keygen_results =
      RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xDB, 0x03, 0x01});
  const std::vector<PartyIndex> signers = {1, 2};
  auto parties = BuildDefaultSignParties(
      keygen_results, Bytes{0xDB, 0x03, 0x01}, Bytes{0xEB, 0x02, 0x01});

  SignRoundState state;
  RunToRound5A(&parties, signers, &state);
  state.round5a.at(1).commitment[0] ^= 0x01;
  state.round5b = CollectRound5BMessages(&parties, signers, state.round5a);

  ExpectThrow(
      [&]() { (void)CollectRound5CMessages(&parties, signers, state.round5b); },
      "receiver must reject tampered round5A commitment");
}

void TestM9TamperedPhase3DeltaShareAbortsAndNoResult() {
  const auto keygen_results =
      RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xDC, 0x03, 0x01});
  const std::vector<PartyIndex> signers = {1, 2};
  auto parties = BuildDefaultSignParties(
      keygen_results, Bytes{0xDC, 0x03, 0x01}, Bytes{0xEC, 0x02, 0x01});

  SignRoundState state;
  RunToRound3(&parties, signers, &state);
  state.round3.at(1).delta_i =
      state.round3.at(1).delta_i + Scalar::FromUint64(1);
  state.round4 = CollectRound4Messages(&parties, signers, state.round3);
  state.round5a = CollectRound5AMessages(&parties, signers, state.round4);
  state.round5b = CollectRound5BMessages(&parties, signers, state.round5a);
  ExpectThrow(
      [&]() { (void)CollectRound5CMessages(&parties, signers, state.round5b); },
      "tampered delta share must break later signing rounds");
}

void TestM9TamperedPhase5BVPointAbortsReceiver() {
  const auto keygen_results =
      RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xDD, 0x03, 0x01});
  const std::vector<PartyIndex> signers = {1, 2};
  auto parties = BuildDefaultSignParties(
      keygen_results, Bytes{0xDD, 0x03, 0x01}, Bytes{0xED, 0x02, 0x01});

  SignRoundState state;
  RunToRound5B(&parties, signers, &state);
  state.round5b.at(1).V_i = state.round5b.at(2).V_i;

  ExpectThrow(
      [&]() { (void)CollectRound5CMessages(&parties, signers, state.round5b); },
      "receiver must reject tampered round5B V_i point");
}

}  // namespace tecdsa::sign_flow_test
