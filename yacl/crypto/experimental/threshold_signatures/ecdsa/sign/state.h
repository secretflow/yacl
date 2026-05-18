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

#include <cstdint>

#include "yacl/crypto/experimental/threshold_signatures/core/protocol/round_driver.h"
#include "yacl/crypto/experimental/threshold_signatures/ecdsa/sign/messages.h"
#include "yacl/crypto/experimental/threshold_signatures/ecdsa/sign/mta_exchange.h"

namespace tecdsa::ecdsa::sign {

enum class SignStep : uint8_t {
  kInit = 0,
  kRound1Done = 1,
  kRound2RequestsDone = 2,
  kRound2ResponsesDone = 3,
  kRound3Done = 4,
  kRound4Done = 5,
  kRound5ADone = 6,
  kRound5BDone = 7,
  kRound5CDone = 8,
  kRound5DDone = 9,
  kRound5EDone = 10,
};

struct Round1State {
  Scalar k_i;
  Scalar gamma_i;
  ECPoint Gamma_i;
  Bytes randomness;
  PeerMap<Bytes> commitments;
};

struct Round2MtaState {
  Round2MtaSums sums;
  Scalar delta_i;
  Scalar sigma_i;
};

struct DeltaState {
  Scalar delta_inv;
  ECPoint gamma;
  ECPoint R;
  Scalar r;
};

struct FinalShareState {
  Scalar s_i;
  Scalar l_i;
  Scalar rho_i;
  ECPoint V_i;
  ECPoint A_i;
  Bytes round5a_randomness;
  PeerMap<Bytes> round5a_commitments;
};

struct ConsistencyState {
  ECPoint V;
  ECPoint A;
  ECPoint U_i;
  ECPoint T_i;
  Bytes round5c_randomness;
  PeerMap<Bytes> round5c_commitments;
};

struct SigningState {
  core::protocol::LinearRoundDriver<SignStep> rounds{SignStep::kInit};
  Round1State round1;
  Round2MtaState round2;
  DeltaState delta;
  FinalShareState final_share;
  ConsistencyState consistency;
};

}  // namespace tecdsa::ecdsa::sign
