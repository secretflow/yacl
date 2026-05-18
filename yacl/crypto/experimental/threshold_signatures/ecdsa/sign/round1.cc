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

#include "yacl/crypto/experimental/threshold_signatures/ecdsa/sign/sign.h"

#include "yacl/crypto/experimental/threshold_signatures/common/errors.h"

namespace tecdsa::ecdsa::sign {

SignRound1Msg SignParty::MakeRound1() {
  if (state_.rounds.HasReached(SignStep::kRound1Done)) {
    TECDSA_THROW_LOGIC("MakeRound1 must not be called twice");
  }
  EnsurePhase1Prepared();
  return SignRound1Msg{
      .commitment = state_.round1.commitments.at(cfg_.self_id)};
}

}  // namespace tecdsa::ecdsa::sign
