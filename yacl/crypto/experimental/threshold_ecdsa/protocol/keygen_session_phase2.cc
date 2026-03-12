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

#include <cstddef>
#include <exception>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/bigint_utils.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/commitment.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/encoding.h"
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/keygen_session.h"
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/keygen_session_internal.h"

namespace tecdsa {
namespace ki = keygen_internal;

void KeygenSession::EnsureLocalPolynomialPrepared() {
  if (!local_poly_coefficients_.empty()) {
    return;
  }

  while (true) {
    std::vector<Scalar> candidate_coefficients;
    candidate_coefficients.reserve(threshold_ + 1);
    candidate_coefficients.push_back(ki::RandomNonZeroScalar());
    for (uint32_t i = 0; i < threshold_; ++i) {
      candidate_coefficients.push_back(ki::RandomNonZeroScalar());
    }

    std::unordered_map<PartyIndex, Scalar> candidate_shares;
    candidate_shares.reserve(participants_.size());
    bool has_zero_share = false;
    for (PartyIndex party : participants_) {
      const Scalar share =
          ki::EvaluatePolynomialAt(candidate_coefficients, party);
      if (share.value() == 0) {
        has_zero_share = true;
        break;
      }
      candidate_shares[party] = share;
    }
    if (has_zero_share) {
      continue;
    }

    local_poly_coefficients_ = std::move(candidate_coefficients);
    local_shares_ = std::move(candidate_shares);
    break;
  }

  local_y_i_ = ECPoint::GeneratorMultiply(local_poly_coefficients_[0]);

  local_vss_commitments_.clear();
  local_vss_commitments_.reserve(local_poly_coefficients_.size());
  for (const Scalar& coefficient : local_poly_coefficients_) {
    local_vss_commitments_.push_back(ECPoint::GeneratorMultiply(coefficient));
  }

  const Bytes y_i_bytes = EncodePoint(local_y_i_);
  const CommitmentResult commit =
      CommitMessage(ki::kPhase1CommitDomain, y_i_bytes);
  local_commitment_ = commit.commitment;
  local_open_randomness_ = commit.randomness;
}

std::vector<Envelope> KeygenSession::BuildPhase2OpenAndShareEnvelopes() {
  if (IsTerminal()) {
    TECDSA_THROW_LOGIC(
        "cannot build phase2 envelopes for terminal keygen session");
  }
  if (phase_ != KeygenPhase::kPhase2) {
    TECDSA_THROW_LOGIC(
        "BuildPhase2OpenAndShareEnvelopes must be called in keygen phase2");
  }

  EnsureLocalPolynomialPrepared();
  local_phase2_ready_ = true;
  phase2_open_data_[self_id()] = Phase2OpenData{
      local_y_i_, local_open_randomness_, local_vss_commitments_};
  phase2_verified_shares_[self_id()] = local_shares_.at(self_id());

  Bytes open_payload;
  open_payload.reserve(ki::kPointCompressedLen + 4 +
                       local_open_randomness_.size() + 4 +
                       ki::kPointCompressedLen * local_vss_commitments_.size());
  ki::AppendPoint(local_y_i_, &open_payload);
  ki::AppendSizedField(local_open_randomness_, &open_payload);
  ki::AppendU32Be(static_cast<uint32_t>(local_vss_commitments_.size()),
                  &open_payload);
  for (const ECPoint& commitment : local_vss_commitments_) {
    ki::AppendPoint(commitment, &open_payload);
  }

  std::vector<Envelope> out;
  out.reserve(1 + peers_.size());

  Envelope open_msg;
  open_msg.session_id = session_id();
  open_msg.from = self_id();
  open_msg.to = kBroadcastPartyId;
  open_msg.type = MessageTypeForPhase(KeygenPhase::kPhase2);
  open_msg.payload = std::move(open_payload);
  out.push_back(std::move(open_msg));

  for (PartyIndex peer : participants_) {
    if (peer == self_id()) {
      continue;
    }
    Envelope share_msg;
    share_msg.session_id = session_id();
    share_msg.from = self_id();
    share_msg.to = peer;
    share_msg.type = Phase2ShareMessageType();
    ki::AppendScalar(local_shares_.at(peer), &share_msg.payload);
    out.push_back(std::move(share_msg));
  }

  MaybeAdvanceAfterPhase2();
  return out;
}

bool KeygenSession::HandlePhase2OpenEnvelope(const Envelope& envelope) {
  if (envelope.to != kBroadcastPartyId) {
    Abort("keygen phase2 open message must be broadcast");
    return false;
  }

  const bool inserted = seen_phase2_opens_.insert(envelope.from).second;
  if (!inserted) {
    return true;
  }

  try {
    size_t offset = 0;
    const ECPoint y_i = ki::ReadPoint(envelope.payload, &offset);
    const Bytes randomness =
        ki::ReadSizedField(envelope.payload, &offset, ki::kMaxOpenRandomnessLen,
                           "keygen phase2 open randomness");
    const uint32_t commitment_count = ki::ReadU32Be(envelope.payload, &offset);
    if (commitment_count != threshold_ + 1) {
      TECDSA_THROW_ARGUMENT(
          "keygen phase2 commitments count does not match threshold");
    }

    std::vector<ECPoint> commitments;
    commitments.reserve(commitment_count);
    for (uint32_t i = 0; i < commitment_count; ++i) {
      commitments.push_back(ki::ReadPoint(envelope.payload, &offset));
    }

    if (offset != envelope.payload.size()) {
      TECDSA_THROW_ARGUMENT("keygen phase2 open payload has trailing bytes");
    }

    const auto commitment_it = phase1_commitments_.find(envelope.from);
    if (commitment_it == phase1_commitments_.end()) {
      TECDSA_THROW_ARGUMENT("missing phase1 commitment for dealer");
    }

    const Bytes y_i_bytes = EncodePoint(y_i);
    if (!VerifyCommitment(ki::kPhase1CommitDomain, y_i_bytes, randomness,
                          commitment_it->second)) {
      TECDSA_THROW_ARGUMENT("phase2 open does not match phase1 commitment");
    }
    if (commitments.empty() || commitments.front() != y_i) {
      TECDSA_THROW_ARGUMENT(
          "phase2 Feldman commitments do not match opened Y_i");
    }

    phase2_open_data_[envelope.from] = Phase2OpenData{
        .y_i = y_i,
        .randomness = randomness,
        .commitments = commitments,
    };

    const auto pending_it = pending_phase2_shares_.find(envelope.from);
    if (pending_it != pending_phase2_shares_.end()) {
      if (!VerifyDealerShareForSelf(envelope.from, pending_it->second)) {
        TECDSA_THROW_ARGUMENT("phase2 Feldman share verification failed");
      }
      phase2_verified_shares_[envelope.from] = pending_it->second;
      pending_phase2_shares_.erase(pending_it);
    }
  } catch (const std::exception& ex) {
    Abort(std::string("invalid keygen phase2 open: ") + ex.what());
    return false;
  }

  Touch();
  MaybeAdvanceAfterPhase2();
  return true;
}

bool KeygenSession::HandlePhase2ShareEnvelope(const Envelope& envelope) {
  if (envelope.to != self_id()) {
    Abort("keygen phase2 share message must target receiver directly");
    return false;
  }

  const bool inserted = seen_phase2_shares_.insert(envelope.from).second;
  if (!inserted) {
    return true;
  }

  try {
    size_t offset = 0;
    const Scalar share = ki::ReadScalar(envelope.payload, &offset);
    if (offset != envelope.payload.size()) {
      TECDSA_THROW_ARGUMENT("keygen phase2 share payload has trailing bytes");
    }

    if (phase2_open_data_.contains(envelope.from)) {
      if (!VerifyDealerShareForSelf(envelope.from, share)) {
        TECDSA_THROW_ARGUMENT("phase2 Feldman share verification failed");
      }
      phase2_verified_shares_[envelope.from] = share;
    } else {
      pending_phase2_shares_[envelope.from] = share;
    }
  } catch (const std::exception& ex) {
    Abort(std::string("invalid keygen phase2 share: ") + ex.what());
    return false;
  }

  Touch();
  MaybeAdvanceAfterPhase2();
  return true;
}

bool KeygenSession::VerifyDealerShareForSelf(PartyIndex dealer,
                                             const Scalar& share) const {
  if (share.value() == 0) {
    return false;
  }

  const auto open_it = phase2_open_data_.find(dealer);
  if (open_it == phase2_open_data_.end()) {
    return false;
  }

  const std::vector<ECPoint>& commitments = open_it->second.commitments;
  if (commitments.size() != threshold_ + 1 || commitments.empty()) {
    return false;
  }

  try {
    ECPoint rhs = commitments[0];
    const BigInt& q = Scalar::ModulusQMpInt();
    const BigInt self = BigInt(self_id());
    BigInt power = self.Mod(q);
    for (size_t k = 1; k < commitments.size(); ++k) {
      rhs = rhs.Add(commitments[k].Mul(Scalar(power)));
      power = bigint::NormalizeMod(power * self, q);
    }

    const ECPoint lhs = ECPoint::GeneratorMultiply(share);
    return lhs == rhs;
  } catch (const std::exception&) {
    return false;
  }
}

void KeygenSession::MaybeAdvanceAfterPhase2() {
  if (phase_ != KeygenPhase::kPhase2) {
    return;
  }
  if (!local_phase2_ready_) {
    return;
  }
  if (seen_phase2_opens_.size() != peers_.size()) {
    return;
  }
  if (seen_phase2_shares_.size() != peers_.size()) {
    return;
  }
  if (!pending_phase2_shares_.empty()) {
    return;
  }
  if (phase2_open_data_.size() != participants_.size()) {
    return;
  }
  if (phase2_verified_shares_.size() != participants_.size()) {
    return;
  }

  ComputePhase2Aggregates();
  if (IsTerminal()) {
    return;
  }
  phase_ = KeygenPhase::kPhase3;
}

void KeygenSession::ComputePhase2Aggregates() {
  Scalar x_sum;
  for (const auto& [dealer, share] : phase2_verified_shares_) {
    (void)dealer;
    x_sum = x_sum + share;
  }
  if (x_sum.value() == 0) {
    Abort("aggregated local share is zero");
    return;
  }

  bool first = true;
  ECPoint y_sum;
  for (PartyIndex party : participants_) {
    const auto open_it = phase2_open_data_.find(party);
    if (open_it == phase2_open_data_.end()) {
      Abort("missing phase2 open data");
      return;
    }
    if (first) {
      y_sum = open_it->second.y_i;
      first = false;
      continue;
    }
    try {
      y_sum = y_sum.Add(open_it->second.y_i);
    } catch (const std::exception& ex) {
      Abort(std::string("failed to aggregate keygen public key points: ") +
            ex.what());
      return;
    }
  }

  result_.x_i = x_sum;
  result_.y = y_sum;
  phase2_aggregates_ready_ = true;
}

}  // namespace tecdsa
