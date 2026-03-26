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

#include <optional>
#include <vector>

#include "yacl/crypto/experimental/threshold_ecdsa/protocol/messages.h"
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/proto_common.h"

namespace tecdsa::proto {

struct SignConfig {
  Bytes session_id;
  Bytes keygen_session_id;
  PartyIndex self_id = 0;
  std::vector<PartyIndex> participants;
  LocalKeyShare local_key_share;
  PublicKeygenData public_keygen_data;
  Bytes msg32;
};

class SignParty {
 public:
  explicit SignParty(SignConfig cfg);

  SignRound1Msg MakeRound1();

 private:
  SignConfig cfg_;
  std::vector<PartyIndex> peers_;

  Scalar message_scalar_;
  Scalar local_k_i_;
  Scalar local_gamma_i_;
  ECPoint local_Gamma_i_;
  Bytes local_round1_randomness_;
  std::optional<SignRound1Msg> round1_;
};

}  // namespace tecdsa::proto
