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

#include "yacl/crypto/experimental/threshold_ecdsa/crypto/strict_proofs.h"
#include "sign_flow_test_shared.h"

namespace {

using tecdsa::BigInt;
using tecdsa::Bytes;
using tecdsa::PartyIndex;
using tecdsa::Scalar;
using tecdsa::proto::BuildProofContext;
using tecdsa::proto::KeygenOutput;
using tecdsa::proto::KeygenRound2Broadcast;
using tecdsa::proto::PeerMap;
using tecdsa::sign_flow_test::BuildParticipants;
using tecdsa::sign_flow_test::BuildParties;
using tecdsa::sign_flow_test::BuildPeerMapFor;
using tecdsa::sign_flow_test::CollectRound1;
using tecdsa::sign_flow_test::CollectRound2;
using tecdsa::sign_flow_test::CollectRound3;
using tecdsa::sign_flow_test::Expect;
using tecdsa::sign_flow_test::ExpectThrow;
using tecdsa::sign_flow_test::FinalizeOutputs;
using tecdsa::sign_flow_test::KeygenOutputs;
using tecdsa::sign_flow_test::KeygenRound2Shares;
using tecdsa::sign_flow_test::RunKeygenAndCollectResults;

void AssertKeygenOutputsConsistent(const KeygenOutputs& outputs,
                                   const std::vector<PartyIndex>& participants,
                                   const Bytes& session_id) {
  const auto& baseline = outputs.at(participants.front());
  Expect(baseline.local_key_share.paillier != nullptr,
         "baseline result must expose local Paillier provider");

  for (PartyIndex party : participants) {
    const auto& current = outputs.at(party);
    Expect(current.local_key_share.x_i.value() != 0,
           "local x_i share must be non-zero");
    Expect(current.local_key_share.paillier != nullptr,
           "local Paillier provider must be present");
    Expect(current.public_keygen_data.y == baseline.public_keygen_data.y,
           "all parties must derive the same public key");
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
    Expect(current.local_key_share.X_i ==
               current.public_keygen_data.all_X_i.at(party),
           "local X_i must match public share map");
    Expect(current.public_keygen_data.all_paillier_public.at(party).n ==
               current.local_key_share.paillier->modulus_n_bigint(),
           "local Paillier provider must match public key");

    for (PartyIndex peer : participants) {
      Expect(current.public_keygen_data.all_X_i.at(peer) ==
                 baseline.public_keygen_data.all_X_i.at(peer),
             "all parties must agree on X_i");
      Expect(current.public_keygen_data.all_paillier_public.at(peer).n ==
                 baseline.public_keygen_data.all_paillier_public.at(peer).n,
             "all parties must agree on Paillier public keys");
      Expect(current.public_keygen_data.all_aux_rsa_params.at(peer).n_tilde ==
                 baseline.public_keygen_data.all_aux_rsa_params.at(peer).n_tilde,
             "all parties must agree on aux n_tilde");
      Expect(current.public_keygen_data.all_aux_rsa_params.at(peer).h1 ==
                 baseline.public_keygen_data.all_aux_rsa_params.at(peer).h1,
             "all parties must agree on aux h1");
      Expect(current.public_keygen_data.all_aux_rsa_params.at(peer).h2 ==
                 baseline.public_keygen_data.all_aux_rsa_params.at(peer).h2,
             "all parties must agree on aux h2");
      Expect(current.public_keygen_data.all_paillier_public.at(peer).n >
                 tecdsa::proto::MinPaillierModulusQ8(),
             "Paillier modulus must satisfy N > q^8");

      const auto proof_ctx = BuildProofContext(session_id, peer);
      Expect(tecdsa::VerifySquareFreeProofGmr98(
                 current.public_keygen_data.all_paillier_public.at(peer).n,
                 current.public_keygen_data.all_square_free_proofs.at(peer),
                 proof_ctx),
             "square-free proof must verify");
      Expect(tecdsa::VerifyAuxRsaParamProofStrict(
                 current.public_keygen_data.all_aux_rsa_params.at(peer),
                 current.public_keygen_data.all_aux_param_proofs.at(peer),
                 proof_ctx),
             "aux parameter proof must verify");
    }
  }
}

void RunHonestKeygenAndAssertConsistency(uint32_t n, uint32_t t,
                                         const Bytes& session_id) {
  const std::vector<PartyIndex> participants = BuildParticipants(n);
  const auto outputs = RunKeygenAndCollectResults(n, t, session_id);
  AssertKeygenOutputsConsistent(outputs, participants, session_id);
}

void TestKeygenConsistencyN3T1() {
  RunHonestKeygenAndAssertConsistency(/*n=*/3, /*t=*/1,
                                      Bytes{0xA1, 0x03, 0x01});
}

void TestKeygenConsistencyN5T2() {
  RunHonestKeygenAndAssertConsistency(/*n=*/5, /*t=*/2,
                                      Bytes{0xA1, 0x05, 0x02});
}

void TestTamperedPhase2ShareAbortsReceiver() {
  auto parties = BuildParties(/*n=*/3, /*t=*/1, Bytes{0xB1, 0x03, 0x01});
  const std::vector<PartyIndex> participants = BuildParticipants(3);
  const auto round1 = CollectRound1(&parties, participants);

  PeerMap<KeygenRound2Broadcast> broadcasts;
  KeygenRound2Shares shares;
  CollectRound2(&parties, participants, round1, &broadcasts, &shares);

  const auto peer_round2 =
      BuildPeerMapFor(participants, /*self_id=*/2, broadcasts);
  PeerMap<Scalar> shares_for_self;
  for (PartyIndex peer : participants) {
    if (peer != 2) {
      shares_for_self.emplace(peer, shares.at(peer).at(2));
    }
  }
  shares_for_self.at(1) = shares_for_self.at(1) + Scalar::FromUint64(1);

  ExpectThrow(
      [&]() { (void)parties.at(2).MakeRound3(peer_round2, shares_for_self); },
      "receiver must reject tampered dealer share");
}

void TestTamperedPhase1PaillierModulusAbortsReceiver() {
  auto parties = BuildParties(/*n=*/3, /*t=*/1, Bytes{0xB2, 0x03, 0x01});
  const std::vector<PartyIndex> participants = BuildParticipants(3);
  auto round1 = CollectRound1(&parties, participants);
  round1.at(1).paillier_public.n = BigInt(17);

  const auto peer_round1 = BuildPeerMapFor(participants, /*self_id=*/2, round1);
  ExpectThrow([&]() { (void)parties.at(2).MakeRound2(peer_round1); },
              "receiver must reject too-small Paillier modulus in round1");
}

void TestTamperedPhase3SchnorrAbortsPeers() {
  auto parties = BuildParties(/*n=*/3, /*t=*/1, Bytes{0xC1, 0x03, 0x01});
  const std::vector<PartyIndex> participants = BuildParticipants(3);
  const auto round1 = CollectRound1(&parties, participants);

  PeerMap<KeygenRound2Broadcast> broadcasts;
  KeygenRound2Shares shares;
  CollectRound2(&parties, participants, round1, &broadcasts, &shares);
  auto round3 = CollectRound3(&parties, participants, broadcasts, shares);
  round3.at(1).proof.z = round3.at(1).proof.z + Scalar::FromUint64(1);

  const auto peer_round3 = BuildPeerMapFor(participants, /*self_id=*/2, round3);
  ExpectThrow([&]() { (void)parties.at(2).Finalize(peer_round3); },
              "receiver must reject tampered round3 Schnorr proof");
}

void TestStrictModeMissingPhase1AuxProofAbortsReceiver() {
  auto parties = BuildParties(/*n=*/3, /*t=*/1, Bytes{0xC2, 0x03, 0x01});
  const std::vector<PartyIndex> participants = BuildParticipants(3);
  auto round1 = CollectRound1(&parties, participants);
  round1.at(1).aux_param_proof.blob.clear();

  const auto peer_round1 = BuildPeerMapFor(participants, /*self_id=*/2, round1);
  ExpectThrow([&]() { (void)parties.at(2).MakeRound2(peer_round1); },
              "receiver must reject missing round1 aux proof");
}

void TestStrictModeTamperedPhase1AuxProofAbortsReceiver() {
  auto parties = BuildParties(/*n=*/3, /*t=*/1, Bytes{0xC7, 0x03, 0x01});
  const std::vector<PartyIndex> participants = BuildParticipants(3);
  auto round1 = CollectRound1(&parties, participants);
  round1.at(1).aux_param_proof.blob.back() ^= 0x01;

  const auto peer_round1 = BuildPeerMapFor(participants, /*self_id=*/2, round1);
  ExpectThrow([&]() { (void)parties.at(2).MakeRound2(peer_round1); },
              "receiver must reject tampered round1 aux proof");
}

void TestStrictModeMalformedAuxParamsProofMismatchAbortsReceiver() {
  auto parties = BuildParties(/*n=*/3, /*t=*/1, Bytes{0xC8, 0x03, 0x01});
  const std::vector<PartyIndex> participants = BuildParticipants(3);
  auto round1 = CollectRound1(&parties, participants);
  round1.at(1).aux_rsa_params.h1 = BigInt(0);

  const auto peer_round1 = BuildPeerMapFor(participants, /*self_id=*/2, round1);
  ExpectThrow([&]() { (void)parties.at(2).MakeRound2(peer_round1); },
              "receiver must reject malformed auxiliary parameters");
}

void TestStrictModeMissingPhase3SquareFreeProofAbortsReceiver() {
  auto parties = BuildParties(/*n=*/3, /*t=*/1, Bytes{0xC4, 0x03, 0x01});
  const std::vector<PartyIndex> participants = BuildParticipants(3);
  const auto round1 = CollectRound1(&parties, participants);

  PeerMap<KeygenRound2Broadcast> broadcasts;
  KeygenRound2Shares shares;
  CollectRound2(&parties, participants, round1, &broadcasts, &shares);
  auto round3 = CollectRound3(&parties, participants, broadcasts, shares);
  round3.at(1).square_free_proof.blob.clear();

  const auto peer_round3 = BuildPeerMapFor(participants, /*self_id=*/2, round3);
  ExpectThrow([&]() { (void)parties.at(2).Finalize(peer_round3); },
              "receiver must reject missing round3 square-free proof");
}

void TestStrictModeTamperedPhase3SquareFreeProofAbortsReceiver() {
  auto parties = BuildParties(/*n=*/3, /*t=*/1, Bytes{0xC9, 0x03, 0x01});
  const std::vector<PartyIndex> participants = BuildParticipants(3);
  const auto round1 = CollectRound1(&parties, participants);

  PeerMap<KeygenRound2Broadcast> broadcasts;
  KeygenRound2Shares shares;
  CollectRound2(&parties, participants, round1, &broadcasts, &shares);
  auto round3 = CollectRound3(&parties, participants, broadcasts, shares);
  round3.at(1).square_free_proof.blob.back() ^= 0x01;

  const auto peer_round3 = BuildPeerMapFor(participants, /*self_id=*/2, round3);
  ExpectThrow([&]() { (void)parties.at(2).Finalize(peer_round3); },
              "receiver must reject tampered round3 square-free proof");
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
    TestStrictModeTamperedPhase1AuxProofAbortsReceiver();
    TestStrictModeMalformedAuxParamsProofMismatchAbortsReceiver();
    TestStrictModeMissingPhase3SquareFreeProofAbortsReceiver();
    TestStrictModeTamperedPhase3SquareFreeProofAbortsReceiver();
  } catch (const std::exception& ex) {
    std::cerr << ex.what() << '\n';
    return 1;
  }

  std::cout << "keygen_flow_tests passed" << '\n';
  return 0;
}
