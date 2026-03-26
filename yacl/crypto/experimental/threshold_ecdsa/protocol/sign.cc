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

#include "yacl/crypto/experimental/threshold_ecdsa/protocol/sign.h"

#include <algorithm>
#include <exception>
#include <optional>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/commitment.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/ecdsa_verify.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/random.h"
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/sign_session_internal.h"

namespace tecdsa::proto {
namespace {

using InternalA1RangeProof = tecdsa::sign_internal::A1RangeProof;
using InternalA2MtAwcProof = tecdsa::sign_internal::A2MtAwcProof;
using InternalA3MtAProof = tecdsa::sign_internal::A3MtAProof;
using InternalMtaProofContext = tecdsa::sign_internal::MtaProofContext;

bool IsPeer(const std::vector<PartyIndex>& peers, PartyIndex party) {
  return std::find(peers.begin(), peers.end(), party) != peers.end();
}

void ValidateCommitmentOrThrow(const Bytes& commitment,
                               const char* field_name) {
  if (commitment.size() != tecdsa::sign_internal::kCommitmentLen) {
    TECDSA_THROW_ARGUMENT(std::string(field_name) +
                          " must be exactly 32 bytes");
  }
}

size_t ExpectedPhase2MessageCount(const std::vector<PartyIndex>& peers) {
  return peers.size() * 2;
}

InternalMtaProofContext BuildMtaContext(const Bytes& session_id,
                                        PartyIndex initiator_id,
                                        PartyIndex responder_id,
                                        const Bytes& instance_id) {
  return InternalMtaProofContext{
      .session_id = session_id,
      .initiator_id = initiator_id,
      .responder_id = responder_id,
      .mta_instance_id = instance_id,
  };
}

InternalA1RangeProof ToInternal(const A1RangeProof& proof) {
  return InternalA1RangeProof{
      .z = proof.z,
      .u = proof.u,
      .w = proof.w,
      .s = proof.s,
      .s1 = proof.s1,
      .s2 = proof.s2,
  };
}

A1RangeProof FromInternal(const InternalA1RangeProof& proof) {
  return A1RangeProof{
      .z = proof.z,
      .u = proof.u,
      .w = proof.w,
      .s = proof.s,
      .s1 = proof.s1,
      .s2 = proof.s2,
  };
}

InternalA2MtAwcProof ToInternal(const A2MtAwcProof& proof) {
  return InternalA2MtAwcProof{
      .u = proof.u,
      .z = proof.z,
      .z2 = proof.z2,
      .t = proof.t,
      .v = proof.v,
      .w = proof.w,
      .s = proof.s,
      .s1 = proof.s1,
      .s2 = proof.s2,
      .t1 = proof.t1,
      .t2 = proof.t2,
  };
}

A2MtAwcProof FromInternal(const InternalA2MtAwcProof& proof) {
  return A2MtAwcProof{
      .u = proof.u,
      .z = proof.z,
      .z2 = proof.z2,
      .t = proof.t,
      .v = proof.v,
      .w = proof.w,
      .s = proof.s,
      .s1 = proof.s1,
      .s2 = proof.s2,
      .t1 = proof.t1,
      .t2 = proof.t2,
  };
}

InternalA3MtAProof ToInternal(const A3MtAProof& proof) {
  return InternalA3MtAProof{
      .z = proof.z,
      .z2 = proof.z2,
      .t = proof.t,
      .v = proof.v,
      .w = proof.w,
      .s = proof.s,
      .s1 = proof.s1,
      .s2 = proof.s2,
      .t1 = proof.t1,
      .t2 = proof.t2,
  };
}

A3MtAProof FromInternal(const InternalA3MtAProof& proof) {
  return A3MtAProof{
      .z = proof.z,
      .z2 = proof.z2,
      .t = proof.t,
      .v = proof.v,
      .w = proof.w,
      .s = proof.s,
      .s1 = proof.s1,
      .s2 = proof.s2,
      .t1 = proof.t1,
      .t2 = proof.t2,
  };
}

A1RangeProof ProveA1Range(const Bytes& session_id, PartyIndex initiator_id,
                          PartyIndex responder_id, const Bytes& instance_id,
                          const BigInt& n, const AuxRsaParams& verifier_aux,
                          const BigInt& c, const BigInt& witness_m,
                          const BigInt& witness_r) {
  return FromInternal(tecdsa::sign_internal::ProveA1Range(
      BuildMtaContext(session_id, initiator_id, responder_id, instance_id), n,
      verifier_aux, c, witness_m, witness_r));
}

bool VerifyA1Range(const Bytes& session_id, PartyIndex initiator_id,
                   PartyIndex responder_id, const Bytes& instance_id,
                   const BigInt& n, const AuxRsaParams& verifier_aux,
                   const BigInt& c, const A1RangeProof& proof) {
  return tecdsa::sign_internal::VerifyA1Range(
      BuildMtaContext(session_id, initiator_id, responder_id, instance_id), n,
      verifier_aux, c, ToInternal(proof));
}

A2MtAwcProof ProveA2MtAwc(const Bytes& session_id, PartyIndex initiator_id,
                          PartyIndex responder_id, const Bytes& instance_id,
                          const BigInt& n, const AuxRsaParams& verifier_aux,
                          const BigInt& c1, const BigInt& c2,
                          const ECPoint& statement_x, const BigInt& witness_x,
                          const BigInt& witness_y, const BigInt& witness_r) {
  return FromInternal(tecdsa::sign_internal::ProveA2MtAwc(
      BuildMtaContext(session_id, initiator_id, responder_id, instance_id), n,
      verifier_aux, c1, c2, statement_x, witness_x, witness_y, witness_r));
}

bool VerifyA2MtAwc(const Bytes& session_id, PartyIndex initiator_id,
                   PartyIndex responder_id, const Bytes& instance_id,
                   const BigInt& n, const AuxRsaParams& verifier_aux,
                   const BigInt& c1, const BigInt& c2,
                   const ECPoint& statement_x, const A2MtAwcProof& proof) {
  return tecdsa::sign_internal::VerifyA2MtAwc(
      BuildMtaContext(session_id, initiator_id, responder_id, instance_id), n,
      verifier_aux, c1, c2, statement_x, ToInternal(proof));
}

A3MtAProof ProveA3MtA(const Bytes& session_id, PartyIndex initiator_id,
                      PartyIndex responder_id, const Bytes& instance_id,
                      const BigInt& n, const AuxRsaParams& verifier_aux,
                      const BigInt& c1, const BigInt& c2,
                      const BigInt& witness_x, const BigInt& witness_y,
                      const BigInt& witness_r) {
  return FromInternal(tecdsa::sign_internal::ProveA3MtA(
      BuildMtaContext(session_id, initiator_id, responder_id, instance_id), n,
      verifier_aux, c1, c2, witness_x, witness_y, witness_r));
}

bool VerifyA3MtA(const Bytes& session_id, PartyIndex initiator_id,
                 PartyIndex responder_id, const Bytes& instance_id,
                 const BigInt& n, const AuxRsaParams& verifier_aux,
                 const BigInt& c1, const BigInt& c2, const A3MtAProof& proof) {
  return tecdsa::sign_internal::VerifyA3MtA(
      BuildMtaContext(session_id, initiator_id, responder_id, instance_id), n,
      verifier_aux, c1, c2, ToInternal(proof));
}

VRelationProof BuildVRelationProof(const Bytes& session_id,
                                   PartyIndex prover_id,
                                   const ECPoint& r_statement,
                                   const ECPoint& v_statement,
                                   const Scalar& s_witness,
                                   const Scalar& l_witness) {
  while (true) {
    const Scalar a = Csprng::RandomScalar();
    const Scalar b = Csprng::RandomScalar();
    if (a.value() == 0 && b.value() == 0) {
      continue;
    }

    ECPoint alpha;
    try {
      alpha = tecdsa::sign_internal::BuildRGeneratorLinearCombination(
          r_statement, a, b);
    } catch (const std::exception&) {
      continue;
    }

    const Scalar c = tecdsa::sign_internal::BuildVRelationChallenge(
        session_id, prover_id, r_statement, v_statement, alpha);
    const Scalar t = a + (c * s_witness);
    const Scalar u = b + (c * l_witness);
    if (t.value() == 0 && u.value() == 0) {
      continue;
    }

    return VRelationProof{
        .alpha = alpha,
        .t = t,
        .u = u,
    };
  }
}

bool VerifyVRelationProof(const Bytes& session_id, PartyIndex prover_id,
                          const ECPoint& r_statement,
                          const ECPoint& v_statement,
                          const VRelationProof& proof) {
  if (proof.t.value() == 0 && proof.u.value() == 0) {
    return false;
  }

  try {
    const Scalar c = tecdsa::sign_internal::BuildVRelationChallenge(
        session_id, prover_id, r_statement, v_statement, proof.alpha);
    const ECPoint lhs = tecdsa::sign_internal::BuildRGeneratorLinearCombination(
        r_statement, proof.t, proof.u);

    ECPoint rhs = proof.alpha;
    if (c.value() != 0) {
      rhs = rhs.Add(v_statement.Mul(c));
    }
    return lhs == rhs;
  } catch (const std::exception&) {
    return false;
  }
}

}  // namespace

SignParty::SignParty(SignConfig cfg)
    : cfg_(std::move(cfg)),
      peers_(BuildPeers(cfg_.participants, cfg_.self_id)),
      message_scalar_(Scalar::FromBigEndianModQ(cfg_.msg32)) {
  ValidateParticipantsOrThrow(cfg_.participants, cfg_.self_id, "SignParty");
  if (cfg_.msg32.size() != 32) {
    TECDSA_THROW_ARGUMENT("msg32 must be exactly 32 bytes for SignParty");
  }
  if (cfg_.local_key_share.x_i.value() == 0) {
    TECDSA_THROW_ARGUMENT("local x_i share must be non-zero");
  }
  if (cfg_.local_key_share.paillier == nullptr) {
    TECDSA_THROW_ARGUMENT("local Paillier provider must be present");
  }
  if (ECPoint::GeneratorMultiply(cfg_.local_key_share.x_i) !=
      cfg_.local_key_share.X_i) {
    TECDSA_THROW_ARGUMENT("local key share X_i does not match x_i");
  }

  for (PartyIndex party : cfg_.participants) {
    if (!cfg_.public_keygen_data.all_X_i.contains(party) ||
        !cfg_.public_keygen_data.all_paillier_public.contains(party) ||
        !cfg_.public_keygen_data.all_aux_rsa_params.contains(party) ||
        !cfg_.public_keygen_data.all_square_free_proofs.contains(party) ||
        !cfg_.public_keygen_data.all_aux_param_proofs.contains(party)) {
      TECDSA_THROW_ARGUMENT("public keygen data is missing participant data");
    }

    const auto& paillier_public =
        cfg_.public_keygen_data.all_paillier_public.at(party);
    const auto& aux_params =
        cfg_.public_keygen_data.all_aux_rsa_params.at(party);
    const auto& square_free_proof =
        cfg_.public_keygen_data.all_square_free_proofs.at(party);
    const auto& aux_param_proof =
        cfg_.public_keygen_data.all_aux_param_proofs.at(party);

    ValidatePaillierPublicKeyOrThrow(paillier_public);
    if (!ValidateAuxRsaParams(aux_params)) {
      TECDSA_THROW_ARGUMENT("public aux RSA parameters are invalid");
    }

    const StrictProofVerifierContext proof_context =
        BuildProofContext(cfg_.keygen_session_id, party);
    if (!VerifySquareFreeProofGmr98(paillier_public.n, square_free_proof,
                                    proof_context)) {
      TECDSA_THROW_ARGUMENT("square-free proof verification failed");
    }
    if (!VerifyAuxRsaParamProofStrict(aux_params, aux_param_proof,
                                      proof_context)) {
      TECDSA_THROW_ARGUMENT("aux parameter proof verification failed");
    }
  }

  const auto self_pk_it =
      cfg_.public_keygen_data.all_paillier_public.find(cfg_.self_id);
  if (self_pk_it == cfg_.public_keygen_data.all_paillier_public.end()) {
    TECDSA_THROW_ARGUMENT("missing self Paillier public key");
  }
  if (self_pk_it->second.n != cfg_.local_key_share.paillier->modulus_n()) {
    TECDSA_THROW_ARGUMENT(
        "self Paillier public key does not match local provider");
  }

  const auto self_x_it = cfg_.public_keygen_data.all_X_i.find(cfg_.self_id);
  if (self_x_it == cfg_.public_keygen_data.all_X_i.end()) {
    TECDSA_THROW_ARGUMENT("missing self X_i in public keygen data");
  }
  if (self_x_it->second != cfg_.local_key_share.X_i) {
    TECDSA_THROW_ARGUMENT("self X_i does not match local key share");
  }

  PrepareResharedSigningShares();
}

const SignConfig& SignParty::config() const { return cfg_; }

void SignParty::PrepareResharedSigningShares() {
  lagrange_coefficients_ = ComputeLagrangeAtZero(cfg_.participants);

  const auto lambda_self_it = lagrange_coefficients_.find(cfg_.self_id);
  if (lambda_self_it == lagrange_coefficients_.end()) {
    TECDSA_THROW_ARGUMENT("missing lagrange coefficient for self");
  }

  local_w_i_ = lambda_self_it->second * cfg_.local_key_share.x_i;

  std::vector<ECPoint> w_points;
  w_points.reserve(cfg_.participants.size());
  for (PartyIndex party : cfg_.participants) {
    const auto lambda_it = lagrange_coefficients_.find(party);
    const auto x_it = cfg_.public_keygen_data.all_X_i.find(party);
    if (lambda_it == lagrange_coefficients_.end() ||
        x_it == cfg_.public_keygen_data.all_X_i.end()) {
      TECDSA_THROW_ARGUMENT(
          "missing lagrange coefficient or X_i for participant");
    }

    try {
      w_points_[party] = x_it->second.Mul(lambda_it->second);
    } catch (const std::exception& ex) {
      TECDSA_THROW_ARGUMENT(std::string("failed to compute W_i: ") + ex.what());
    }
    w_points.push_back(w_points_.at(party));
  }

  try {
    const ECPoint reconstructed_y = SumPointsOrThrow(w_points);
    if (reconstructed_y != cfg_.public_keygen_data.y) {
      TECDSA_THROW_ARGUMENT("W_i aggregation does not reconstruct y");
    }
  } catch (const std::exception& ex) {
    TECDSA_THROW_ARGUMENT(std::string("failed to validate W_i aggregation: ") +
                          ex.what());
  }
}

void SignParty::EnsurePhase1Prepared() {
  if (round1_.has_value()) {
    return;
  }

  local_k_i_ = RandomNonZeroScalar();
  local_gamma_i_ = RandomNonZeroScalar();
  local_Gamma_i_ = ECPoint::GeneratorMultiply(local_gamma_i_);

  const CommitmentResult commit =
      CommitMessage(tecdsa::sign_internal::kPhase1CommitDomain,
                    local_Gamma_i_.ToCompressedBytes());
  local_round1_randomness_ = commit.randomness;
  round1_ = SignRound1Msg{.commitment = commit.commitment};
  phase1_commitments_[cfg_.self_id] = round1_->commitment;
}

void SignParty::EnsureRound5ASharePrepared() {
  if (round5a_.has_value()) {
    return;
  }

  local_s_i_ = (message_scalar_ * local_k_i_) + (r_ * local_sigma_i_);
  local_l_i_ = RandomNonZeroScalar();
  local_rho_i_ = RandomNonZeroScalar();

  local_V_i_ = ECPoint::GeneratorMultiply(local_l_i_);
  if (local_s_i_.value() != 0) {
    local_V_i_ = local_V_i_.Add(R_.Mul(local_s_i_));
  }
  local_A_i_ = ECPoint::GeneratorMultiply(local_rho_i_);

  const CommitmentResult commit = CommitMessage(
      tecdsa::sign_internal::kPhase5ACommitDomain,
      tecdsa::sign_internal::SerializePointPair(local_V_i_, local_A_i_));
  local_round5a_randomness_ = commit.randomness;
  round5a_ = SignRound5AMsg{.commitment = commit.commitment};
  phase5a_commitments_[cfg_.self_id] = round5a_->commitment;
}

SignRound1Msg SignParty::MakeRound1() {
  EnsurePhase1Prepared();
  return *round1_;
}

std::vector<SignRound2Request> SignParty::MakeRound2Requests(
    const PeerMap<SignRound1Msg>& peer_round1) {
  if (!round2_requests_.empty()) {
    return round2_requests_;
  }

  EnsurePhase1Prepared();
  RequireExactlyPeers(peer_round1, cfg_.participants, cfg_.self_id,
                      "peer_round1");

  for (PartyIndex peer : peers_) {
    const SignRound1Msg& msg = peer_round1.at(peer);
    ValidateCommitmentOrThrow(msg.commitment, "sign round1 commitment");
    phase1_commitments_[peer] = msg.commitment;
  }

  std::unordered_set<std::string> reserved_instance_keys;
  reserved_instance_keys.reserve(ExpectedPhase2MessageCount(peers_));

  const BigInt local_n = cfg_.local_key_share.paillier->modulus_n_bigint();
  const BigInt local_k_value = local_k_i_.mp_value();
  for (PartyIndex peer : peers_) {
    const auto aux_it = cfg_.public_keygen_data.all_aux_rsa_params.find(peer);
    if (aux_it == cfg_.public_keygen_data.all_aux_rsa_params.end()) {
      TECDSA_THROW_LOGIC("missing peer auxiliary parameters for sign round2");
    }

    for (MtaType type : {MtaType::kTimesGamma, MtaType::kTimesW}) {
      Bytes instance_id = tecdsa::sign_internal::RandomMtaInstanceId();
      std::string instance_key = tecdsa::sign_internal::BytesToKey(instance_id);
      while (phase2_initiator_instances_.contains(instance_key) ||
             reserved_instance_keys.contains(instance_key)) {
        instance_id = tecdsa::sign_internal::RandomMtaInstanceId();
        instance_key = tecdsa::sign_internal::BytesToKey(instance_id);
      }
      reserved_instance_keys.insert(instance_key);

      const PaillierCiphertextWithRandomBigInt encrypted =
          cfg_.local_key_share.paillier->EncryptWithRandomBigInt(local_k_value);
      const A1RangeProof a1_proof =
          ProveA1Range(cfg_.session_id, cfg_.self_id, peer, instance_id,
                       local_n, aux_it->second, encrypted.ciphertext,
                       local_k_value, encrypted.randomness);

      round2_requests_.push_back(SignRound2Request{
          .from = cfg_.self_id,
          .to = peer,
          .type = type,
          .instance_id = instance_id,
          .c1 = encrypted.ciphertext,
          .a1_proof = a1_proof,
      });
      phase2_initiator_instances_.emplace(instance_key,
                                          Phase2InitiatorInstance{
                                              .responder = peer,
                                              .type = type,
                                              .instance_id = instance_id,
                                              .c1 = encrypted.ciphertext,
                                          });
    }
  }

  return round2_requests_;
}

std::vector<SignRound2Response> SignParty::MakeRound2Responses(
    const std::vector<SignRound2Request>& requests_for_self) {
  if (round2_responses_.has_value()) {
    return *round2_responses_;
  }
  if (round2_requests_.empty()) {
    TECDSA_THROW_LOGIC(
        "MakeRound2Requests must be completed before MakeRound2Responses");
  }
  if (requests_for_self.size() != ExpectedPhase2MessageCount(peers_)) {
    TECDSA_THROW_ARGUMENT(
        "requests_for_self must contain exactly one request per peer/type");
  }

  std::unordered_set<std::string> seen_request_keys;
  std::unordered_set<std::string> seen_instance_keys;
  seen_request_keys.reserve(requests_for_self.size());
  seen_instance_keys.reserve(requests_for_self.size());

  std::vector<SignRound2Response> out;
  out.reserve(requests_for_self.size());
  for (const SignRound2Request& request : requests_for_self) {
    if (!IsPeer(peers_, request.from)) {
      TECDSA_THROW_ARGUMENT("round2 request sender is not a peer");
    }
    if (request.to != cfg_.self_id) {
      TECDSA_THROW_ARGUMENT("round2 request must target self");
    }
    if (request.instance_id.size() !=
        tecdsa::sign_internal::kMtaInstanceIdLen) {
      TECDSA_THROW_ARGUMENT("round2 request instance id has invalid length");
    }

    const std::string request_key =
        tecdsa::sign_internal::MakeResponderRequestKey(
            request.from, static_cast<uint8_t>(request.type));
    if (!seen_request_keys.insert(request_key).second) {
      TECDSA_THROW_ARGUMENT("duplicate round2 request for sender/type");
    }

    const std::string instance_key =
        tecdsa::sign_internal::BytesToKey(request.instance_id);
    if (!seen_instance_keys.insert(instance_key).second) {
      TECDSA_THROW_ARGUMENT("duplicate round2 request instance id");
    }

    const BigInt n =
        cfg_.public_keygen_data.all_paillier_public.at(request.from).n;
    const BigInt n2 = n * n;
    if (request.c1 < 0 || request.c1 >= n2) {
      TECDSA_THROW_ARGUMENT("round2 request ciphertext c1 is out of range");
    }

    const auto self_aux_it =
        cfg_.public_keygen_data.all_aux_rsa_params.find(cfg_.self_id);
    if (self_aux_it == cfg_.public_keygen_data.all_aux_rsa_params.end()) {
      TECDSA_THROW_LOGIC("missing responder auxiliary parameters");
    }
    if (!VerifyA1Range(cfg_.session_id, request.from, cfg_.self_id,
                       request.instance_id, n, self_aux_it->second, request.c1,
                       request.a1_proof)) {
      TECDSA_THROW_ARGUMENT("round2 A1 proof verification failed");
    }

    const Scalar witness =
        (request.type == MtaType::kTimesGamma) ? local_gamma_i_ : local_w_i_;
    const BigInt y =
        tecdsa::sign_internal::RandomBelow(tecdsa::sign_internal::QPow5());
    const BigInt r_b = tecdsa::sign_internal::SampleZnStar(n);
    const BigInt gamma = n + BigInt(1);
    const BigInt c1_pow_x =
        tecdsa::sign_internal::PowMod(request.c1, witness.mp_value(), n2);
    const BigInt gamma_pow_y = tecdsa::sign_internal::PowMod(gamma, y, n2);
    const BigInt r_pow_n = tecdsa::sign_internal::PowMod(r_b, n, n2);
    const BigInt c2 = tecdsa::sign_internal::MulMod(
        tecdsa::sign_internal::MulMod(c1_pow_x, gamma_pow_y, n2), r_pow_n, n2);

    const Scalar responder_share(-y);
    if (request.type == MtaType::kTimesGamma) {
      phase2_mta_responder_sum_ = phase2_mta_responder_sum_ + responder_share;
    } else {
      phase2_mtawc_responder_sum_ =
          phase2_mtawc_responder_sum_ + responder_share;
    }

    SignRound2Response response{
        .from = cfg_.self_id,
        .to = request.from,
        .type = request.type,
        .instance_id = request.instance_id,
        .c2 = c2,
        .a2_proof = std::nullopt,
        .a3_proof = std::nullopt,
    };

    const auto initiator_aux_it =
        cfg_.public_keygen_data.all_aux_rsa_params.find(request.from);
    if (initiator_aux_it == cfg_.public_keygen_data.all_aux_rsa_params.end()) {
      TECDSA_THROW_LOGIC("missing initiator auxiliary parameters");
    }
    if (request.type == MtaType::kTimesGamma) {
      response.a3_proof = ProveA3MtA(
          cfg_.session_id, request.from, cfg_.self_id, request.instance_id, n,
          initiator_aux_it->second, request.c1, c2, witness.mp_value(), y, r_b);
    } else {
      response.a2_proof = ProveA2MtAwc(
          cfg_.session_id, request.from, cfg_.self_id, request.instance_id, n,
          initiator_aux_it->second, request.c1, c2, w_points_.at(cfg_.self_id),
          witness.mp_value(), y, r_b);
    }
    out.push_back(std::move(response));
  }

  round2_responses_ = out;
  return *round2_responses_;
}

SignRound3Msg SignParty::MakeRound3(
    const std::vector<SignRound2Response>& responses_for_self) {
  if (round3_.has_value()) {
    return *round3_;
  }
  if (!round2_responses_.has_value()) {
    TECDSA_THROW_LOGIC(
        "MakeRound2Responses must be completed before MakeRound3");
  }
  if (responses_for_self.size() != phase2_initiator_instances_.size()) {
    TECDSA_THROW_ARGUMENT(
        "responses_for_self must contain exactly one response per request");
  }

  std::unordered_set<std::string> seen_request_keys;
  std::unordered_set<std::string> seen_instance_keys;
  seen_request_keys.reserve(responses_for_self.size());
  seen_instance_keys.reserve(responses_for_self.size());

  const BigInt self_n = cfg_.local_key_share.paillier->modulus_n_bigint();
  const BigInt self_n2 = self_n * self_n;
  const auto self_aux_it =
      cfg_.public_keygen_data.all_aux_rsa_params.find(cfg_.self_id);
  if (self_aux_it == cfg_.public_keygen_data.all_aux_rsa_params.end()) {
    TECDSA_THROW_LOGIC("missing initiator auxiliary parameters");
  }

  for (const SignRound2Response& response : responses_for_self) {
    if (!IsPeer(peers_, response.from)) {
      TECDSA_THROW_ARGUMENT("round2 response sender is not a peer");
    }
    if (response.to != cfg_.self_id) {
      TECDSA_THROW_ARGUMENT("round2 response must target self");
    }
    if (response.instance_id.size() !=
        tecdsa::sign_internal::kMtaInstanceIdLen) {
      TECDSA_THROW_ARGUMENT("round2 response instance id has invalid length");
    }

    const std::string instance_key =
        tecdsa::sign_internal::BytesToKey(response.instance_id);
    if (!seen_instance_keys.insert(instance_key).second) {
      TECDSA_THROW_ARGUMENT("duplicate round2 response instance id");
    }

    const auto instance_it = phase2_initiator_instances_.find(instance_key);
    if (instance_it == phase2_initiator_instances_.end()) {
      TECDSA_THROW_ARGUMENT("unknown round2 response instance id");
    }
    const Phase2InitiatorInstance& instance = instance_it->second;
    if (instance.responder != response.from) {
      TECDSA_THROW_ARGUMENT("round2 response sender mismatch");
    }
    if (instance.type != response.type) {
      TECDSA_THROW_ARGUMENT("round2 response type mismatch");
    }

    const std::string request_key =
        tecdsa::sign_internal::MakeResponderRequestKey(
            response.from, static_cast<uint8_t>(response.type));
    if (!seen_request_keys.insert(request_key).second) {
      TECDSA_THROW_ARGUMENT("duplicate round2 response for sender/type");
    }

    if (response.c2 < 0 || response.c2 >= self_n2) {
      TECDSA_THROW_ARGUMENT("round2 response ciphertext c2 is out of range");
    }

    if (response.type == MtaType::kTimesGamma) {
      if (!response.a3_proof.has_value() || response.a2_proof.has_value()) {
        TECDSA_THROW_ARGUMENT("round2 MtA response must carry only A3 proof");
      }
      if (!VerifyA3MtA(cfg_.session_id, cfg_.self_id, response.from,
                       response.instance_id, self_n, self_aux_it->second,
                       instance.c1, response.c2, *response.a3_proof)) {
        TECDSA_THROW_ARGUMENT("round2 A3 proof verification failed");
      }
    } else {
      if (!response.a2_proof.has_value() || response.a3_proof.has_value()) {
        TECDSA_THROW_ARGUMENT("round2 MtAwc response must carry only A2 proof");
      }
      if (!VerifyA2MtAwc(cfg_.session_id, cfg_.self_id, response.from,
                         response.instance_id, self_n, self_aux_it->second,
                         instance.c1, response.c2, w_points_.at(response.from),
                         *response.a2_proof)) {
        TECDSA_THROW_ARGUMENT("round2 A2 proof verification failed");
      }
    }

    const Scalar initiator_share(
        cfg_.local_key_share.paillier->DecryptBigInt(response.c2));
    if (response.type == MtaType::kTimesGamma) {
      phase2_mta_initiator_sum_ = phase2_mta_initiator_sum_ + initiator_share;
    } else {
      phase2_mtawc_initiator_sum_ =
          phase2_mtawc_initiator_sum_ + initiator_share;
    }
  }

  local_delta_i_ = (local_k_i_ * local_gamma_i_) + phase2_mta_initiator_sum_ +
                   phase2_mta_responder_sum_;
  local_sigma_i_ = (local_k_i_ * local_w_i_) + phase2_mtawc_initiator_sum_ +
                   phase2_mtawc_responder_sum_;
  round3_ = SignRound3Msg{.delta_i = local_delta_i_};
  return *round3_;
}

SignRound4Msg SignParty::MakeRound4(const PeerMap<SignRound3Msg>& peer_round3) {
  if (round4_.has_value()) {
    return *round4_;
  }
  if (!round3_.has_value()) {
    TECDSA_THROW_LOGIC("MakeRound3 must be completed before MakeRound4");
  }

  RequireExactlyPeers(peer_round3, cfg_.participants, cfg_.self_id,
                      "peer_round3");
  Scalar delta = local_delta_i_;
  for (PartyIndex peer : peers_) {
    delta = delta + peer_round3.at(peer).delta_i;
  }
  if (delta.value() == 0) {
    TECDSA_THROW_ARGUMENT("aggregated delta is zero");
  }

  const std::optional<Scalar> delta_inv =
      tecdsa::sign_internal::InvertScalar(delta);
  if (!delta_inv.has_value()) {
    TECDSA_THROW_ARGUMENT("failed to invert aggregated delta");
  }
  delta_inv_ = *delta_inv;

  round4_ = SignRound4Msg{
      .gamma_i = local_Gamma_i_,
      .randomness = local_round1_randomness_,
      .gamma_proof = BuildSchnorrProof(cfg_.session_id, cfg_.self_id,
                                       local_Gamma_i_, local_gamma_i_),
  };
  return *round4_;
}

SignRound5AMsg SignParty::MakeRound5A(
    const PeerMap<SignRound4Msg>& peer_round4) {
  if (round5a_.has_value()) {
    return *round5a_;
  }
  if (!round4_.has_value()) {
    TECDSA_THROW_LOGIC("MakeRound4 must be completed before MakeRound5A");
  }

  RequireExactlyPeers(peer_round4, cfg_.participants, cfg_.self_id,
                      "peer_round4");
  std::vector<ECPoint> gamma_points;
  gamma_points.reserve(cfg_.participants.size());
  gamma_points.push_back(local_Gamma_i_);

  for (PartyIndex peer : peers_) {
    const SignRound4Msg& msg = peer_round4.at(peer);
    const auto commitment_it = phase1_commitments_.find(peer);
    if (commitment_it == phase1_commitments_.end()) {
      TECDSA_THROW_LOGIC("missing stored round1 commitment for peer");
    }
    if (!VerifyCommitment(tecdsa::sign_internal::kPhase1CommitDomain,
                          msg.gamma_i.ToCompressedBytes(), msg.randomness,
                          commitment_it->second)) {
      TECDSA_THROW_ARGUMENT(
          "round4 gamma opening does not match round1 commitment");
    }
    if (!VerifySchnorrProof(cfg_.session_id, peer, msg.gamma_i,
                            msg.gamma_proof)) {
      TECDSA_THROW_ARGUMENT("round4 gamma Schnorr proof verification failed");
    }
    gamma_points.push_back(msg.gamma_i);
  }

  try {
    gamma_ = SumPointsOrThrow(gamma_points);
    R_ = gamma_.Mul(delta_inv_);
  } catch (const std::exception& ex) {
    TECDSA_THROW_ARGUMENT(std::string("failed to compute R in round5A: ") +
                          ex.what());
  }
  r_ = XCoordinateModQ(R_);
  if (r_.value() == 0) {
    TECDSA_THROW_ARGUMENT("computed r is zero");
  }

  EnsureRound5ASharePrepared();
  return *round5a_;
}

SignRound5BMsg SignParty::MakeRound5B(
    const PeerMap<SignRound5AMsg>& peer_round5a) {
  if (round5b_.has_value()) {
    return *round5b_;
  }
  if (!round5a_.has_value()) {
    TECDSA_THROW_LOGIC("MakeRound5A must be completed before MakeRound5B");
  }

  RequireExactlyPeers(peer_round5a, cfg_.participants, cfg_.self_id,
                      "peer_round5a");
  for (PartyIndex peer : peers_) {
    ValidateCommitmentOrThrow(peer_round5a.at(peer).commitment,
                              "sign round5A commitment");
    phase5a_commitments_[peer] = peer_round5a.at(peer).commitment;
  }

  round5b_ = SignRound5BMsg{
      .V_i = local_V_i_,
      .A_i = local_A_i_,
      .randomness = local_round5a_randomness_,
      .a_schnorr_proof = BuildSchnorrProof(cfg_.session_id, cfg_.self_id,
                                           local_A_i_, local_rho_i_),
      .v_relation_proof =
          BuildVRelationProof(cfg_.session_id, cfg_.self_id, R_, local_V_i_,
                              local_s_i_, local_l_i_),
  };
  return *round5b_;
}

SignRound5CMsg SignParty::MakeRound5C(
    const PeerMap<SignRound5BMsg>& peer_round5b) {
  if (round5c_.has_value()) {
    return *round5c_;
  }
  if (!round5b_.has_value()) {
    TECDSA_THROW_LOGIC("MakeRound5B must be completed before MakeRound5C");
  }

  RequireExactlyPeers(peer_round5b, cfg_.participants, cfg_.self_id,
                      "peer_round5b");

  std::vector<ECPoint> v_points;
  std::vector<ECPoint> a_points;
  v_points.reserve(cfg_.participants.size());
  a_points.reserve(cfg_.participants.size());
  v_points.push_back(local_V_i_);
  a_points.push_back(local_A_i_);

  for (PartyIndex peer : peers_) {
    const SignRound5BMsg& msg = peer_round5b.at(peer);
    const auto commitment_it = phase5a_commitments_.find(peer);
    if (commitment_it == phase5a_commitments_.end()) {
      TECDSA_THROW_LOGIC("missing stored round5A commitment for peer");
    }

    if (!VerifyCommitment(
            tecdsa::sign_internal::kPhase5ACommitDomain,
            tecdsa::sign_internal::SerializePointPair(msg.V_i, msg.A_i),
            msg.randomness, commitment_it->second)) {
      TECDSA_THROW_ARGUMENT(
          "round5B opening does not match round5A commitment");
    }
    if (!VerifySchnorrProof(cfg_.session_id, peer, msg.A_i,
                            msg.a_schnorr_proof)) {
      TECDSA_THROW_ARGUMENT("round5B A_i Schnorr proof verification failed");
    }
    if (!VerifyVRelationProof(cfg_.session_id, peer, R_, msg.V_i,
                              msg.v_relation_proof)) {
      TECDSA_THROW_ARGUMENT("round5B V relation proof verification failed");
    }

    v_points.push_back(msg.V_i);
    a_points.push_back(msg.A_i);
  }

  try {
    V_ = SumPointsOrThrow(v_points);
    A_ = SumPointsOrThrow(a_points);
    if (message_scalar_.value() != 0) {
      V_ = V_.Add(ECPoint::GeneratorMultiply(Scalar() - message_scalar_));
    }
    V_ = V_.Add(cfg_.public_keygen_data.y.Mul(Scalar() - r_));
    local_U_i_ = V_.Mul(local_rho_i_);
    local_T_i_ = A_.Mul(local_l_i_);
  } catch (const std::exception& ex) {
    TECDSA_THROW_ARGUMENT(std::string("failed to compute round5C values: ") +
                          ex.what());
  }

  const CommitmentResult commit = CommitMessage(
      tecdsa::sign_internal::kPhase5CCommitDomain,
      tecdsa::sign_internal::SerializePointPair(local_U_i_, local_T_i_));
  local_round5c_randomness_ = commit.randomness;
  round5c_ = SignRound5CMsg{.commitment = commit.commitment};
  phase5c_commitments_[cfg_.self_id] = round5c_->commitment;
  return *round5c_;
}

SignRound5DMsg SignParty::MakeRound5D(
    const PeerMap<SignRound5CMsg>& peer_round5c) {
  if (round5d_.has_value()) {
    return *round5d_;
  }
  if (!round5c_.has_value()) {
    TECDSA_THROW_LOGIC("MakeRound5C must be completed before MakeRound5D");
  }

  RequireExactlyPeers(peer_round5c, cfg_.participants, cfg_.self_id,
                      "peer_round5c");
  for (PartyIndex peer : peers_) {
    ValidateCommitmentOrThrow(peer_round5c.at(peer).commitment,
                              "sign round5C commitment");
    phase5c_commitments_[peer] = peer_round5c.at(peer).commitment;
  }

  round5d_ = SignRound5DMsg{
      .U_i = local_U_i_,
      .T_i = local_T_i_,
      .randomness = local_round5c_randomness_,
  };
  return *round5d_;
}

Scalar SignParty::RevealRound5E(const PeerMap<SignRound5DMsg>& peer_round5d) {
  if (round5e_.has_value()) {
    return *round5e_;
  }
  if (!round5d_.has_value()) {
    TECDSA_THROW_LOGIC("MakeRound5D must be completed before RevealRound5E");
  }

  RequireExactlyPeers(peer_round5d, cfg_.participants, cfg_.self_id,
                      "peer_round5d");
  std::vector<ECPoint> u_points;
  std::vector<ECPoint> t_points;
  u_points.reserve(cfg_.participants.size());
  t_points.reserve(cfg_.participants.size());
  u_points.push_back(local_U_i_);
  t_points.push_back(local_T_i_);

  for (PartyIndex peer : peers_) {
    const SignRound5DMsg& msg = peer_round5d.at(peer);
    const auto commitment_it = phase5c_commitments_.find(peer);
    if (commitment_it == phase5c_commitments_.end()) {
      TECDSA_THROW_LOGIC("missing stored round5C commitment for peer");
    }
    if (!VerifyCommitment(
            tecdsa::sign_internal::kPhase5CCommitDomain,
            tecdsa::sign_internal::SerializePointPair(msg.U_i, msg.T_i),
            msg.randomness, commitment_it->second)) {
      TECDSA_THROW_ARGUMENT(
          "round5D opening does not match round5C commitment");
    }
    u_points.push_back(msg.U_i);
    t_points.push_back(msg.T_i);
  }

  try {
    const ECPoint sum_u = SumPointsOrThrow(u_points);
    const ECPoint sum_t = SumPointsOrThrow(t_points);
    if (sum_u != sum_t) {
      TECDSA_THROW_ARGUMENT("round5D consistency check failed");
    }
  } catch (const std::exception& ex) {
    TECDSA_THROW_ARGUMENT(std::string("failed to validate round5D: ") +
                          ex.what());
  }

  round5e_ = local_s_i_;
  return *round5e_;
}

Signature SignParty::Finalize(const PeerMap<Scalar>& peer_round5e) {
  if (signature_.has_value()) {
    return *signature_;
  }
  if (!round5e_.has_value()) {
    TECDSA_THROW_LOGIC("RevealRound5E must be completed before Finalize");
  }

  RequireExactlyPeers(peer_round5e, cfg_.participants, cfg_.self_id,
                      "peer_round5e");
  Scalar s = *round5e_;
  for (PartyIndex peer : peers_) {
    s = s + peer_round5e.at(peer);
  }
  if (s.value() == 0) {
    TECDSA_THROW_ARGUMENT("aggregated signature scalar s is zero");
  }

  Scalar canonical_s = s;
  if (IsHighScalar(canonical_s)) {
    canonical_s = Scalar() - canonical_s;
  }
  if (!VerifyEcdsaSignatureMath(cfg_.public_keygen_data.y, cfg_.msg32, r_,
                                canonical_s)) {
    TECDSA_THROW_ARGUMENT("final ECDSA signature verification failed");
  }

  signature_ = Signature{
      .r = r_,
      .s = canonical_s,
      .R = R_,
  };
  return *signature_;
}

}  // namespace tecdsa::proto
