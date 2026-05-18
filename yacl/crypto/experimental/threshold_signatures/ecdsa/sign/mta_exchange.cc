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

#include "yacl/crypto/experimental/threshold_signatures/ecdsa/sign/mta_exchange.h"

#include <array>
#include <utility>

#include "yacl/crypto/experimental/threshold_signatures/common/errors.h"

namespace tecdsa::ecdsa::sign {
namespace {

namespace mta = tecdsa::core::mta;

mta::MtaType ToCoreMtaType(MtaType type) {
  switch (type) {
    case MtaType::kTimesGamma:
      return mta::MtaType::kMta;
    case MtaType::kTimesW:
      return mta::MtaType::kMtAwc;
  }
  TECDSA_THROW_ARGUMENT("unknown protocol MtaType");
}

MtaType FromCoreMtaType(mta::MtaType type) {
  switch (type) {
    case mta::MtaType::kMta:
      return MtaType::kTimesGamma;
    case mta::MtaType::kMtAwc:
      return MtaType::kTimesW;
  }
  TECDSA_THROW_ARGUMENT("unknown core MtaType");
}

SignRound2Request ToProtocolRequest(
    const mta::PairwiseProductRequest& request) {
  return SignRound2Request{
      .from = request.from,
      .to = request.to,
      .type = FromCoreMtaType(request.type),
      .instance_id = request.instance_id,
      .c1 = request.c1,
      .a1_proof = request.a1_proof,
  };
}

mta::PairwiseProductRequest ToCoreRequest(const SignRound2Request& request) {
  return mta::PairwiseProductRequest{
      .from = request.from,
      .to = request.to,
      .type = ToCoreMtaType(request.type),
      .instance_id = request.instance_id,
      .c1 = request.c1,
      .a1_proof = request.a1_proof,
  };
}

SignRound2Response ToProtocolResponse(
    const mta::PairwiseProductResponse& response) {
  return SignRound2Response{
      .from = response.from,
      .to = response.to,
      .type = FromCoreMtaType(response.type),
      .instance_id = response.instance_id,
      .c2 = response.c2,
      .a2_proof = response.a2_proof,
      .a3_proof = response.a3_proof,
  };
}

mta::PairwiseProductResponse ToCoreResponse(
    const SignRound2Response& response) {
  return mta::PairwiseProductResponse{
      .from = response.from,
      .to = response.to,
      .type = ToCoreMtaType(response.type),
      .instance_id = response.instance_id,
      .c2 = response.c2,
      .a2_proof = response.a2_proof,
      .a3_proof = response.a3_proof,
  };
}

void AddShare(Round2MtaSums* sums, MtaType type, bool initiator,
              const Scalar& share) {
  if (type == MtaType::kTimesGamma) {
    if (initiator) {
      sums->delta_initiator = sums->delta_initiator + share;
    } else {
      sums->delta_responder = sums->delta_responder + share;
    }
    return;
  }
  if (initiator) {
    sums->sigma_initiator = sums->sigma_initiator + share;
  } else {
    sums->sigma_responder = sums->sigma_responder + share;
  }
}

}  // namespace

SigningMtaExchange::SigningMtaExchange(Config cfg)
    : session_({.session_id = std::move(cfg.session_id),
                .self_id = cfg.self_id,
                .suite = std::move(cfg.suite),
                .group = std::move(cfg.group)}),
      self_id_(cfg.self_id) {}

std::vector<SignRound2Request> SigningMtaExchange::CreateRequests(
    std::span<const PartyIndex> peers,
    const keygen::LocalKeyShare& local_key_share,
    const keygen::VerifiedPublicKeygenData& public_data,
    const Scalar& local_k_i) {
  std::vector<SignRound2Request> out;
  out.reserve(peers.size() * 2);
  for (PartyIndex peer : peers) {
    const auto& peer_aux = public_data.AuxOf(peer);
    out.push_back(ToProtocolRequest(session_.InitiatorInit({
        .responder_id = peer,
        .initiator_paillier = local_key_share.paillier.get(),
        .responder_aux = &peer_aux,
        .initiator_secret = local_k_i,
    })));
    out.push_back(ToProtocolRequest(session_.InitiatorInitWithCheck({
        .responder_id = peer,
        .initiator_paillier = local_key_share.paillier.get(),
        .responder_aux = &peer_aux,
        .initiator_secret = local_k_i,
    })));
  }
  return out;
}

Round2ResponseBatch SigningMtaExchange::ConsumeRequests(
    const std::vector<SignRound2Request>& requests_for_self,
    std::span<const PartyIndex> peers,
    const keygen::VerifiedPublicKeygenData& public_data,
    const Scalar& local_gamma_i, const Scalar& local_w_i,
    const PeerMap<ECPoint>& w_points) {
  const std::array<mta::MtaType, 2> expected_types = {
      mta::MtaType::kMta, mta::MtaType::kMtAwc};
  mta::RequireExactlyOneRequestPerPeerAndType(
      requests_for_self, peers, self_id_, expected_types, ToCoreRequest,
      "round2 request");

  Round2ResponseBatch out;
  out.messages.reserve(requests_for_self.size());
  const auto& self_aux = public_data.AuxOf(self_id_);
  for (const SignRound2Request& request : requests_for_self) {
    const Scalar witness =
        (request.type == MtaType::kTimesGamma) ? local_gamma_i : local_w_i;
    auto consume_result =
        request.type == MtaType::kTimesGamma
            ? session_.ResponderMid(
                  ToCoreRequest(request),
                  {.initiator_modulus_n =
                       public_data.PaillierOf(request.from).n,
                   .responder_aux = &self_aux,
                   .initiator_aux = &public_data.AuxOf(request.from),
                   .responder_secret = witness})
            : session_.ResponderMidWithCheck(
                  ToCoreRequest(request),
                  {.initiator_modulus_n =
                       public_data.PaillierOf(request.from).n,
                   .responder_aux = &self_aux,
                   .initiator_aux = &public_data.AuxOf(request.from),
                   .responder_secret = witness,
                   .public_witness_point = w_points.at(self_id_)});
    AddShare(&out.sums, request.type, false, consume_result.responder_share);
    out.messages.push_back(ToProtocolResponse(consume_result.response));
  }
  return out;
}

Round2MtaSums SigningMtaExchange::ConsumeResponses(
    const std::vector<SignRound2Response>& responses_for_self,
    std::span<const PartyIndex> peers,
    const keygen::LocalKeyShare& local_key_share,
    const keygen::VerifiedPublicKeygenData& public_data,
    const PeerMap<ECPoint>& w_points) {
  mta::RequireExactlyOneResponsePerInitiatorInstance(
      responses_for_self, peers, peers.size() * 2, self_id_, session_,
      ToCoreResponse, "round2 response");

  Round2MtaSums sums;
  const auto& self_aux = public_data.AuxOf(self_id_);
  for (const SignRound2Response& response : responses_for_self) {
    auto consume_result =
        response.type == MtaType::kTimesGamma
            ? session_.InitiatorEnd(
                  ToCoreResponse(response),
                  {.initiator_paillier = local_key_share.paillier.get(),
                   .initiator_aux = &self_aux})
            : session_.InitiatorEndWithCheck(
                  ToCoreResponse(response),
                  {.initiator_paillier = local_key_share.paillier.get(),
                   .initiator_aux = &self_aux,
                   .public_witness_point = w_points.at(response.from)});
    AddShare(&sums, response.type, true, consume_result.initiator_share);
  }
  return sums;
}

}  // namespace tecdsa::ecdsa::sign
