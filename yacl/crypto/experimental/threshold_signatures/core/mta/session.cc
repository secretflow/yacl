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

#include "yacl/crypto/experimental/threshold_signatures/core/mta/session.h"

#include <exception>
#include <utility>

#include "yacl/crypto/experimental/threshold_signatures/common/errors.h"
#include "yacl/crypto/experimental/threshold_signatures/core/bigint/bigint_utils.h"
#include "yacl/crypto/experimental/threshold_signatures/core/random/csprng.h"

namespace tecdsa::core::mta {
namespace {

std::shared_ptr<const GroupContext> ResolveGroup(
    const ThresholdSuite& suite, std::shared_ptr<const GroupContext> group) {
  if (group == nullptr) {
    group = GroupContext::Create(suite.curve);
  }
  if (group->curve_id() != suite.curve) {
    TECDSA_THROW_ARGUMENT("PairwiseProductSession group must match suite curve");
  }
  return group;
}

void ValidateMtAwcSecretPointOrThrow(
    const Scalar& responder_secret, const ECPoint& public_witness_point) {
  try {
    if (ECPoint::GeneratorMultiply(responder_secret) != public_witness_point) {
      TECDSA_THROW_ARGUMENT(
          "MtAwc public witness point does not match responder secret");
    }
  } catch (const std::exception& ex) {
    TECDSA_THROW_ARGUMENT(std::string("failed to validate MtAwc point: ") +
                          ex.what());
  }
}

void ValidatePublicWitnessPointPresenceOrThrow(
    MtaType type, const ECPoint* public_witness_point,
    const char* context_name) {
  if (RequiresPublicPoint(type)) {
    if (public_witness_point == nullptr) {
      TECDSA_THROW_ARGUMENT(std::string(context_name) +
                            " requires a public witness point");
    }
    return;
  }
  if (public_witness_point != nullptr) {
    TECDSA_THROW_ARGUMENT(std::string(context_name) +
                          " does not use a public witness point");
  }
}

void ValidateExpectedMtaTypeOrThrow(MtaType actual, MtaType expected,
                                    const char* context_name) {
  if (actual != expected) {
    TECDSA_THROW_ARGUMENT(std::string(context_name) + " type mismatch");
  }
}

}  // namespace

Bytes RandomMtaInstanceId() { return Csprng::RandomBytes(kMtaInstanceIdLen); }

std::string BytesToKey(const Bytes& bytes) {
  return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

std::string MtaTypeKey(MtaType type) {
  switch (type) {
    case MtaType::kMta:
      return "mta";
    case MtaType::kMtAwc:
      return "mtawc";
  }
  TECDSA_THROW_ARGUMENT("unknown MtaType");
}

PairwiseProductSession::PairwiseProductSession(Config cfg)
    : cfg_(std::move(cfg)) {
  if (!cfg_.suite.has_value()) {
    TECDSA_THROW_ARGUMENT("PairwiseProductSession suite must be explicit");
  }
  cfg_.group = ResolveGroup(*cfg_.suite, std::move(cfg_.group));
}

void PairwiseProductSession::RegisterInitiatorInstance(
    PairwiseProductInitiatorInstance instance) {
  if (instance.instance_id.size() != kMtaInstanceIdLen) {
    TECDSA_THROW_ARGUMENT("initiator instance id has invalid length");
  }

  const std::string instance_key = BytesToKey(instance.instance_id);
  if (consumed_request_keys_.contains(instance_key)) {
    TECDSA_THROW_ARGUMENT("initiator instance id conflicts with a consumed request");
  }
  generated_instance_keys_.insert(instance_key);
  if (!pending_initiator_instances_
           .emplace(instance_key, std::move(instance))
           .second) {
    TECDSA_THROW_ARGUMENT("duplicate initiator instance id");
  }
}

const PairwiseProductInitiatorInstance&
PairwiseProductSession::GetInitiatorInstance(const Bytes& instance_id) const {
  const std::string instance_key = BytesToKey(instance_id);
  const auto it = pending_initiator_instances_.find(instance_key);
  if (it == pending_initiator_instances_.end()) {
    TECDSA_THROW_ARGUMENT("unknown initiator instance id");
  }
  return it->second;
}

PairwiseProductRequest PairwiseProductSession::InitiatorInit(
    const InitiatorInitArgs& args) {
  return CreateRequestImpl(MtaType::kMta, args);
}

PairwiseProductRequest PairwiseProductSession::InitiatorInitWithCheck(
    const InitiatorInitArgs& args) {
  return CreateRequestImpl(MtaType::kMtAwc, args);
}

PairwiseProductRequest PairwiseProductSession::CreateRequestImpl(
    MtaType type, const InitiatorInitArgs& args) {
  if (args.initiator_paillier == nullptr) {
    TECDSA_THROW_ARGUMENT("initiator Paillier provider must be present");
  }
  if (args.responder_aux == nullptr) {
    TECDSA_THROW_ARGUMENT("responder auxiliary parameters must be present");
  }
  if (args.responder_id == cfg_.self_id) {
    TECDSA_THROW_ARGUMENT("responder id must be a peer");
  }

  const Bytes instance_id = ReserveFreshInstanceId();
  const BigInt n = args.initiator_paillier->modulus_n_bigint();
  const PaillierCiphertextWithRandomBigInt encrypted =
      args.initiator_paillier->EncryptWithRandomBigInt(
          args.initiator_secret.mp_value());

  const A1RangeProof a1_proof = ProveA1Range(
      BuildProofContext(cfg_.session_id, cfg_.self_id, args.responder_id,
                        instance_id, *cfg_.suite, cfg_.group),
      n, *args.responder_aux, encrypted.ciphertext,
      args.initiator_secret.mp_value(), encrypted.randomness);

  RegisterInitiatorInstance(PairwiseProductInitiatorInstance{
      .responder = args.responder_id,
      .type = type,
      .instance_id = instance_id,
      .c1 = encrypted.ciphertext,
  });
  return PairwiseProductRequest{
      .from = cfg_.self_id,
      .to = args.responder_id,
      .type = type,
      .instance_id = instance_id,
      .c1 = encrypted.ciphertext,
      .a1_proof = a1_proof,
  };
}

PairwiseProductSession::ConsumeRequestResult
PairwiseProductSession::ResponderMid(const PairwiseProductRequest& request,
                                     const ResponderMidArgs& args) {
  return ConsumeRequestImpl(request, MtaType::kMta, args.initiator_modulus_n,
                            args.responder_aux, args.initiator_aux,
                            args.responder_secret, nullptr);
}

PairwiseProductSession::ConsumeRequestResult
PairwiseProductSession::ResponderMidWithCheck(
    const PairwiseProductRequest& request,
    const ResponderMidWithCheckArgs& args) {
  return ConsumeRequestImpl(request, MtaType::kMtAwc,
                            args.initiator_modulus_n, args.responder_aux,
                            args.initiator_aux, args.responder_secret,
                            &args.public_witness_point);
}

PairwiseProductSession::ConsumeRequestResult
PairwiseProductSession::ConsumeRequestImpl(
    const PairwiseProductRequest& request, MtaType expected_type,
    const BigInt& initiator_modulus_n, const AuxRsaParams* responder_aux,
    const AuxRsaParams* initiator_aux, const Scalar& responder_secret,
    const ECPoint* public_witness_point) {
  ValidateExpectedMtaTypeOrThrow(request.type, expected_type,
                                 "pairwise product request");
  if (responder_aux == nullptr) {
    TECDSA_THROW_ARGUMENT("responder auxiliary parameters must be present");
  }
  if (initiator_aux == nullptr) {
    TECDSA_THROW_ARGUMENT("initiator auxiliary parameters must be present");
  }
  if (request.to != cfg_.self_id) {
    TECDSA_THROW_ARGUMENT("pairwise product request must target self");
  }
  if (request.from == cfg_.self_id) {
    TECDSA_THROW_ARGUMENT("pairwise product request sender must be a peer");
  }
  if (request.instance_id.size() != kMtaInstanceIdLen) {
    TECDSA_THROW_ARGUMENT("pairwise product request instance id has invalid length");
  }

  const std::string instance_key = BytesToKey(request.instance_id);
  if (generated_instance_keys_.contains(instance_key) ||
      consumed_request_keys_.contains(instance_key)) {
    TECDSA_THROW_ARGUMENT("duplicate pairwise product request instance id");
  }

  const BigInt n = initiator_modulus_n;
  const BigInt n2 = n * n;
  if (request.c1 < 0 || request.c1 >= n2) {
    TECDSA_THROW_ARGUMENT("pairwise product request ciphertext c1 is out of range");
  }

  if (!VerifyA1Range(
          BuildProofContext(cfg_.session_id, request.from, cfg_.self_id,
                            request.instance_id, *cfg_.suite, cfg_.group),
          n, *responder_aux, request.c1, request.a1_proof)) {
    TECDSA_THROW_ARGUMENT("pairwise product A1 proof verification failed");
  }

  ValidatePublicWitnessPointPresenceOrThrow(request.type,
                                            public_witness_point,
                                            "pairwise product responder input");
  if (request.type == MtaType::kMtAwc) {
    ValidateMtAwcSecretPointOrThrow(responder_secret,
                                    *public_witness_point);
  }

  const BigInt y = RandomBelow(QPow5(cfg_.group));
  const BigInt r_b = SampleZnStar(n);
  const BigInt gamma = n + BigInt(1);
  const BigInt c1_pow_x =
      PowMod(request.c1, responder_secret.mp_value(), n2);
  const BigInt gamma_pow_y = PowMod(gamma, y, n2);
  const BigInt r_pow_n = PowMod(r_b, n, n2);
  const BigInt c2 =
      MulMod(MulMod(c1_pow_x, gamma_pow_y, n2), r_pow_n, n2);

  PairwiseProductResponse response{
      .from = cfg_.self_id,
      .to = request.from,
      .type = request.type,
      .instance_id = request.instance_id,
      .c2 = c2,
      .a2_proof = std::nullopt,
      .a3_proof = std::nullopt,
  };

  if (request.type == MtaType::kMta) {
    response.a3_proof = ProveA3MtA(
        BuildProofContext(cfg_.session_id, request.from, cfg_.self_id,
                          request.instance_id, *cfg_.suite, cfg_.group),
        n, *initiator_aux, request.c1, c2,
        responder_secret.mp_value(), y, r_b);
  } else {
    response.a2_proof = ProveA2MtAwc(
        BuildProofContext(cfg_.session_id, request.from, cfg_.self_id,
                          request.instance_id, *cfg_.suite, cfg_.group),
        n, *initiator_aux, request.c1, c2, *public_witness_point,
        responder_secret.mp_value(), y, r_b);
  }

  consumed_request_keys_.insert(instance_key);
  return ConsumeRequestResult{
      .response = std::move(response),
      .responder_share = Scalar(-y, cfg_.group),
  };
}

PairwiseProductSession::ConsumeResponseResult
PairwiseProductSession::InitiatorEnd(const PairwiseProductResponse& response,
                                     const InitiatorEndArgs& args) {
  return ConsumeResponseImpl(response, MtaType::kMta, args.initiator_paillier,
                             args.initiator_aux, nullptr);
}

PairwiseProductSession::ConsumeResponseResult
PairwiseProductSession::InitiatorEndWithCheck(
    const PairwiseProductResponse& response,
    const InitiatorEndWithCheckArgs& args) {
  return ConsumeResponseImpl(response, MtaType::kMtAwc,
                             args.initiator_paillier, args.initiator_aux,
                             &args.public_witness_point);
}

PairwiseProductSession::ConsumeResponseResult
PairwiseProductSession::ConsumeResponseImpl(
    const PairwiseProductResponse& response, MtaType expected_type,
    const PaillierProvider* initiator_paillier,
    const AuxRsaParams* initiator_aux, const ECPoint* public_witness_point) {
  ValidateExpectedMtaTypeOrThrow(response.type, expected_type,
                                 "pairwise product response");
  if (initiator_paillier == nullptr) {
    TECDSA_THROW_ARGUMENT("initiator Paillier provider must be present");
  }
  if (initiator_aux == nullptr) {
    TECDSA_THROW_ARGUMENT("initiator auxiliary parameters must be present");
  }
  if (response.to != cfg_.self_id) {
    TECDSA_THROW_ARGUMENT("pairwise product response must target self");
  }
  if (response.from == cfg_.self_id) {
    TECDSA_THROW_ARGUMENT("pairwise product response sender must be a peer");
  }
  if (response.instance_id.size() != kMtaInstanceIdLen) {
    TECDSA_THROW_ARGUMENT("pairwise product response instance id has invalid length");
  }

  const std::string instance_key = BytesToKey(response.instance_id);
  const auto instance_it = pending_initiator_instances_.find(instance_key);
  if (instance_it == pending_initiator_instances_.end()) {
    TECDSA_THROW_ARGUMENT("unknown pairwise product response instance id");
  }
  const PairwiseProductInitiatorInstance& instance = instance_it->second;
  if (instance.responder != response.from) {
    TECDSA_THROW_ARGUMENT("pairwise product response sender mismatch");
  }
  if (instance.type != response.type) {
    TECDSA_THROW_ARGUMENT("pairwise product response type mismatch");
  }

  const BigInt n = initiator_paillier->modulus_n_bigint();
  const BigInt n2 = n * n;
  if (response.c2 < 0 || response.c2 >= n2) {
    TECDSA_THROW_ARGUMENT("pairwise product response ciphertext c2 is out of range");
  }

  ValidatePublicWitnessPointPresenceOrThrow(response.type,
                                            public_witness_point,
                                            "pairwise product response input");

  if (response.type == MtaType::kMta) {
    if (!response.a3_proof.has_value() || response.a2_proof.has_value()) {
      TECDSA_THROW_ARGUMENT("MtA response must carry only an A3 proof");
    }
    if (!VerifyA3MtA(
            BuildProofContext(cfg_.session_id, cfg_.self_id, response.from,
                              response.instance_id, *cfg_.suite, cfg_.group),
            n, *initiator_aux, instance.c1, response.c2,
            *response.a3_proof)) {
      TECDSA_THROW_ARGUMENT("pairwise product A3 proof verification failed");
    }
  } else {
    if (!response.a2_proof.has_value() || response.a3_proof.has_value()) {
      TECDSA_THROW_ARGUMENT("MtAwc response must carry only an A2 proof");
    }
    if (!VerifyA2MtAwc(
            BuildProofContext(cfg_.session_id, cfg_.self_id, response.from,
                              response.instance_id, *cfg_.suite, cfg_.group),
            n, *initiator_aux, instance.c1, response.c2,
            *public_witness_point, *response.a2_proof)) {
      TECDSA_THROW_ARGUMENT("pairwise product A2 proof verification failed");
    }
  }

  const Scalar initiator_share(
      initiator_paillier->DecryptBigInt(response.c2), cfg_.group);
  pending_initiator_instances_.erase(instance_it);
  return ConsumeResponseResult{.initiator_share = initiator_share};
}

Bytes PairwiseProductSession::ReserveFreshInstanceId() {
  while (true) {
    Bytes instance_id = RandomMtaInstanceId();
    const std::string instance_key = BytesToKey(instance_id);
    if (generated_instance_keys_.contains(instance_key) ||
        consumed_request_keys_.contains(instance_key)) {
      continue;
    }
    generated_instance_keys_.insert(instance_key);
    return instance_id;
  }
}

}  // namespace tecdsa::core::mta
