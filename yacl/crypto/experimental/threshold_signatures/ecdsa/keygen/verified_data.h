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
#include <utility>
#include <vector>

#include "yacl/crypto/experimental/threshold_signatures/core/suite/group_context.h"
#include "yacl/crypto/experimental/threshold_signatures/core/suite/suite.h"
#include "yacl/crypto/experimental/threshold_signatures/ecdsa/keygen/messages.h"

namespace tecdsa::ecdsa::keygen {

class VerifiedPublicKeygenData {
 public:
  VerifiedPublicKeygenData() = default;

  static VerifiedPublicKeygenData Create(
      const PublicKeygenData& public_data, const Bytes& keygen_session_id,
      const core::ThresholdSuite& suite,
      const std::shared_ptr<const core::GroupContext>& group,
      std::span<const PartyIndex> participants, PartyIndex self_id,
      const LocalKeyShare& local_key_share);

  const PublicKeygenData& raw() const;
  const PaillierPublicKey& PaillierOf(PartyIndex party) const;
  const AuxRsaParams& AuxOf(PartyIndex party) const;
  const ECPoint& XOf(PartyIndex party) const;

 private:
  explicit VerifiedPublicKeygenData(PublicKeygenData public_data)
      : public_data_(std::move(public_data)), initialized_(true) {}

  PublicKeygenData public_data_;
  bool initialized_ = false;
};

}  // namespace tecdsa::ecdsa::keygen
