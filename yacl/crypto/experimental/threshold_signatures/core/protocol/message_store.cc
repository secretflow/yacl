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

#include "yacl/crypto/experimental/threshold_signatures/core/protocol/message_store.h"

#include <utility>

namespace tecdsa::core::protocol {

bool IsPeer(std::span<const PartyIndex> peers, PartyIndex party) {
  for (PartyIndex peer : peers) {
    if (peer == party) {
      return true;
    }
  }
  return false;
}

std::string MakePeerTypeKey(PartyIndex peer, std::string_view type_key) {
  std::string out;
  out.reserve(sizeof(PartyIndex) + type_key.size());
  out.push_back(static_cast<char>((peer >> 24) & 0xFF));
  out.push_back(static_cast<char>((peer >> 16) & 0xFF));
  out.push_back(static_cast<char>((peer >> 8) & 0xFF));
  out.push_back(static_cast<char>(peer & 0xFF));
  out.append(type_key.data(), type_key.size());
  return out;
}

PeerTypeMessageStore::PeerTypeMessageStore(
    std::span<const PartyIndex> peers, PartyIndex self_id,
    std::span<const std::string_view> expected_type_keys,
    std::string message_name)
    : peers_(peers.begin(), peers.end()),
      self_id_(self_id),
      message_name_(std::move(message_name)) {
  expected_type_keys_.reserve(expected_type_keys.size());
  for (std::string_view type_key : expected_type_keys) {
    expected_type_keys_.emplace(type_key);
  }
  seen_keys_.reserve(peers_.size() * expected_type_keys_.size());
}

void PeerTypeMessageStore::RequireExpectedCount(size_t count) const {
  if (count != peers_.size() * expected_type_keys_.size()) {
    TECDSA_THROW_ARGUMENT(message_name_ +
                          " must contain exactly one message per peer/type");
  }
}

void PeerTypeMessageStore::Add(PartyIndex sender, PartyIndex receiver,
                               std::string_view type_key) {
  if (!IsPeer(peers_, sender)) {
    TECDSA_THROW_ARGUMENT(message_name_ + " sender is not a peer");
  }
  if (receiver != self_id_) {
    TECDSA_THROW_ARGUMENT(message_name_ + " must target self");
  }
  if (!expected_type_keys_.contains(std::string(type_key))) {
    TECDSA_THROW_ARGUMENT(message_name_ + " has unexpected type");
  }
  if (!seen_keys_.insert(MakePeerTypeKey(sender, type_key)).second) {
    TECDSA_THROW_ARGUMENT("duplicate " + message_name_ + " for sender/type");
  }
}

}  // namespace tecdsa::core::protocol
