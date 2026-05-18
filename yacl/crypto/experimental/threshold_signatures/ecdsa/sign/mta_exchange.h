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

#include <memory>
#include <span>
#include <vector>

#include "yacl/crypto/experimental/threshold_signatures/core/mta/session.h"
#include "yacl/crypto/experimental/threshold_signatures/core/suite/group_context.h"
#include "yacl/crypto/experimental/threshold_signatures/core/suite/suite.h"
#include "yacl/crypto/experimental/threshold_signatures/ecdsa/keygen/verified_data.h"
#include "yacl/crypto/experimental/threshold_signatures/ecdsa/sign/messages.h"

namespace tecdsa::ecdsa::sign {

struct Round2MtaSums {
  Scalar delta_initiator;
  Scalar delta_responder;
  Scalar sigma_initiator;
  Scalar sigma_responder;
};

struct Round2ResponseBatch {
  std::vector<SignRound2Response> messages;
  Round2MtaSums sums;
};

class SigningMtaExchange {
 public:
  struct Config {
    Bytes session_id;
    PartyIndex self_id = 0;
    core::ThresholdSuite suite;
    std::shared_ptr<const core::GroupContext> group;
  };

  explicit SigningMtaExchange(Config cfg);

  std::vector<SignRound2Request> CreateRequests(
      std::span<const PartyIndex> peers,
      const keygen::LocalKeyShare& local_key_share,
      const keygen::VerifiedPublicKeygenData& public_data,
      const Scalar& local_k_i);

  Round2ResponseBatch ConsumeRequests(
      const std::vector<SignRound2Request>& requests_for_self,
      std::span<const PartyIndex> peers,
      const keygen::VerifiedPublicKeygenData& public_data,
      const Scalar& local_gamma_i, const Scalar& local_w_i,
      const PeerMap<ECPoint>& w_points);

  Round2MtaSums ConsumeResponses(
      const std::vector<SignRound2Response>& responses_for_self,
      std::span<const PartyIndex> peers,
      const keygen::LocalKeyShare& local_key_share,
      const keygen::VerifiedPublicKeygenData& public_data,
      const PeerMap<ECPoint>& w_points);

 private:
  core::mta::PairwiseProductSession session_;
  PartyIndex self_id_ = 0;
};

}  // namespace tecdsa::ecdsa::sign
