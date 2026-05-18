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
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "yacl/crypto/experimental/threshold_signatures/common/errors.h"
#include "yacl/crypto/experimental/threshold_signatures/core/mta/messages.h"
#include "yacl/crypto/experimental/threshold_signatures/core/paillier/paillier.h"
#include "yacl/crypto/experimental/threshold_signatures/core/protocol/message_store.h"
#include "yacl/crypto/experimental/threshold_signatures/core/suite/group_context.h"
#include "yacl/crypto/experimental/threshold_signatures/core/suite/suite.h"

namespace tecdsa::core::mta {

using PaillierProvider = core::paillier::PaillierProvider;
using PaillierCiphertextWithRandomBigInt =
    core::paillier::PaillierCiphertextWithRandomBigInt;

Bytes RandomMtaInstanceId();
std::string BytesToKey(const Bytes& bytes);
std::string MtaTypeKey(MtaType type);

template <typename Request, typename ToCoreRequest>
void RequireExactlyOneRequestPerPeerAndType(
    const std::vector<Request>& requests, std::span<const PartyIndex> peers,
    PartyIndex self_id, std::span<const MtaType> expected_types,
    ToCoreRequest to_core_request, const std::string& message_name) {
  std::vector<std::string> expected_type_storage;
  std::vector<std::string_view> expected_type_keys;
  expected_type_storage.reserve(expected_types.size());
  expected_type_keys.reserve(expected_types.size());
  for (MtaType type : expected_types) {
    expected_type_storage.push_back(MtaTypeKey(type));
    expected_type_keys.push_back(expected_type_storage.back());
  }
  tecdsa::core::protocol::PeerTypeMessageStore peer_type_messages(
      peers, self_id, expected_type_keys, message_name);
  peer_type_messages.RequireExpectedCount(requests.size());

  std::unordered_set<std::string> seen_instance_keys;
  seen_instance_keys.reserve(requests.size());
  for (const auto& request : requests) {
    const PairwiseProductRequest core_request = to_core_request(request);
    peer_type_messages.Add(core_request.from, core_request.to,
                           MtaTypeKey(core_request.type));
    if (core_request.instance_id.size() != kMtaInstanceIdLen) {
      TECDSA_THROW_ARGUMENT(message_name + " instance id has invalid length");
    }

    const std::string instance_key = BytesToKey(core_request.instance_id);
    if (!seen_instance_keys.insert(instance_key).second) {
      TECDSA_THROW_ARGUMENT("duplicate " + message_name + " instance id");
    }
  }
}

template <typename Request, typename ToCoreRequest>
void RequireExactlyOneRequestPerPeer(
    const std::vector<Request>& requests, std::span<const PartyIndex> peers,
    PartyIndex self_id, MtaType expected_type, ToCoreRequest to_core_request,
    const std::string& message_name) {
  const MtaType expected_types[] = {expected_type};
  RequireExactlyOneRequestPerPeerAndType(
      requests, peers, self_id, std::span<const MtaType>(expected_types),
      to_core_request, message_name);
}

struct PairwiseProductInitiatorInstance {
  PartyIndex responder = 0;
  MtaType type = MtaType::kMta;
  Bytes instance_id;
  BigInt c1 = BigInt(0);
};

class PairwiseProductSession {
 public:
  struct Config {
    Bytes session_id;
    PartyIndex self_id = 0;
    std::optional<ThresholdSuite> suite;
    std::shared_ptr<const GroupContext> group;
  };

  struct InitiatorInitArgs {
    PartyIndex responder_id = 0;
    const PaillierProvider* initiator_paillier = nullptr;
    const AuxRsaParams* responder_aux = nullptr;
    Scalar initiator_secret;
  };

  struct ResponderMidArgs {
    BigInt initiator_modulus_n = BigInt(0);
    const AuxRsaParams* responder_aux = nullptr;
    const AuxRsaParams* initiator_aux = nullptr;
    Scalar responder_secret;
  };

  struct ResponderMidWithCheckArgs {
    BigInt initiator_modulus_n = BigInt(0);
    const AuxRsaParams* responder_aux = nullptr;
    const AuxRsaParams* initiator_aux = nullptr;
    Scalar responder_secret;
    const ECPoint& public_witness_point;
  };

  struct ConsumeRequestResult {
    PairwiseProductResponse response;
    Scalar responder_share;
  };

  struct InitiatorEndArgs {
    const PaillierProvider* initiator_paillier = nullptr;
    const AuxRsaParams* initiator_aux = nullptr;
  };

  struct InitiatorEndWithCheckArgs {
    const PaillierProvider* initiator_paillier = nullptr;
    const AuxRsaParams* initiator_aux = nullptr;
    const ECPoint& public_witness_point;
  };

  struct ConsumeResponseResult {
    Scalar initiator_share;
  };

  explicit PairwiseProductSession(Config cfg);

  const PairwiseProductInitiatorInstance& GetInitiatorInstance(
      const Bytes& instance_id) const;

  PairwiseProductRequest InitiatorInit(const InitiatorInitArgs& args);
  PairwiseProductRequest InitiatorInitWithCheck(
      const InitiatorInitArgs& args);
  ConsumeRequestResult ResponderMid(const PairwiseProductRequest& request,
                                    const ResponderMidArgs& args);
  ConsumeRequestResult ResponderMidWithCheck(
      const PairwiseProductRequest& request,
      const ResponderMidWithCheckArgs& args);
  ConsumeResponseResult InitiatorEnd(const PairwiseProductResponse& response,
                                     const InitiatorEndArgs& args);
  ConsumeResponseResult InitiatorEndWithCheck(
      const PairwiseProductResponse& response,
      const InitiatorEndWithCheckArgs& args);

 private:
  PairwiseProductRequest CreateRequestImpl(MtaType type,
                                           const InitiatorInitArgs& args);
  ConsumeRequestResult ConsumeRequestImpl(
      const PairwiseProductRequest& request, MtaType expected_type,
      const BigInt& initiator_modulus_n, const AuxRsaParams* responder_aux,
      const AuxRsaParams* initiator_aux, const Scalar& responder_secret,
      const ECPoint* public_witness_point);
  ConsumeResponseResult ConsumeResponseImpl(
      const PairwiseProductResponse& response, MtaType expected_type,
      const PaillierProvider* initiator_paillier,
      const AuxRsaParams* initiator_aux, const ECPoint* public_witness_point);
  Bytes ReserveFreshInstanceId();
  void RegisterInitiatorInstance(PairwiseProductInitiatorInstance instance);

  Config cfg_;
  std::unordered_map<std::string, PairwiseProductInitiatorInstance>
      pending_initiator_instances_;
  std::unordered_set<std::string> generated_instance_keys_;
  std::unordered_set<std::string> consumed_request_keys_;
};

template <typename Response, typename ToCoreResponse>
void RequireExactlyOneResponsePerInitiatorInstance(
    const std::vector<Response>& responses, std::span<const PartyIndex> peers,
    size_t expected_response_count, PartyIndex self_id,
    const PairwiseProductSession& session, ToCoreResponse to_core_response,
    const std::string& message_name) {
  if (responses.size() != expected_response_count) {
    TECDSA_THROW_ARGUMENT(message_name +
                          " must contain exactly one response per request");
  }

  std::unordered_set<std::string> seen_request_keys;
  std::unordered_set<std::string> seen_instance_keys;
  seen_request_keys.reserve(responses.size());
  seen_instance_keys.reserve(responses.size());
  for (const auto& response : responses) {
    const PairwiseProductResponse core_response = to_core_response(response);
    if (!tecdsa::core::protocol::IsPeer(peers, core_response.from)) {
      TECDSA_THROW_ARGUMENT(message_name + " sender is not a peer");
    }
    if (core_response.to != self_id) {
      TECDSA_THROW_ARGUMENT(message_name + " must target self");
    }
    if (core_response.instance_id.size() != kMtaInstanceIdLen) {
      TECDSA_THROW_ARGUMENT(message_name + " instance id has invalid length");
    }

    const std::string instance_key = BytesToKey(core_response.instance_id);
    if (!seen_instance_keys.insert(instance_key).second) {
      TECDSA_THROW_ARGUMENT("duplicate " + message_name + " instance id");
    }

    const auto& instance =
        session.GetInitiatorInstance(core_response.instance_id);
    if (instance.responder != core_response.from) {
      TECDSA_THROW_ARGUMENT(message_name + " sender mismatch");
    }
    if (instance.type != core_response.type) {
      TECDSA_THROW_ARGUMENT(message_name + " type mismatch");
    }
    const std::string request_key =
        tecdsa::core::protocol::MakePeerTypeKey(
            core_response.from, MtaTypeKey(core_response.type));
    if (!seen_request_keys.insert(request_key).second) {
      TECDSA_THROW_ARGUMENT("duplicate " + message_name + " for sender/type");
    }
  }
}

}  // namespace tecdsa::core::mta
