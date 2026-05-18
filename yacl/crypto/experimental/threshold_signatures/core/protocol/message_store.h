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

#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "yacl/crypto/experimental/threshold_signatures/common/errors.h"
#include "yacl/crypto/experimental/threshold_signatures/common/ids.h"

namespace tecdsa::core::protocol {

bool IsPeer(std::span<const PartyIndex> peers, PartyIndex party);

std::string MakePeerTypeKey(PartyIndex peer, std::string_view type_key);

class PeerTypeMessageStore {
 public:
  PeerTypeMessageStore(std::span<const PartyIndex> peers, PartyIndex self_id,
                       std::span<const std::string_view> expected_type_keys,
                       std::string message_name);

  void RequireExpectedCount(size_t count) const;
  void Add(PartyIndex sender, PartyIndex receiver, std::string_view type_key);

 private:
  std::vector<PartyIndex> peers_;
  PartyIndex self_id_ = 0;
  std::unordered_set<std::string> expected_type_keys_;
  std::unordered_set<std::string> seen_keys_;
  std::string message_name_;
};

template <typename MapType>
void RequireExactlyPeerMessages(const MapType& messages,
                                std::span<const PartyIndex> peers,
                                const char* field_name) {
  if (messages.size() != peers.size()) {
    TECDSA_THROW_ARGUMENT(std::string(field_name) +
                          " must contain exactly one entry per peer");
  }
  for (PartyIndex peer : peers) {
    if (!messages.contains(peer)) {
      TECDSA_THROW_ARGUMENT(std::string(field_name) +
                            " is missing a peer message");
    }
  }
}

template <typename T>
std::vector<T> ValuesInPeerOrder(const std::unordered_map<PartyIndex, T>& map,
                                 std::span<const PartyIndex> peers,
                                 const char* field_name) {
  RequireExactlyPeerMessages(map, peers, field_name);
  std::vector<T> out;
  out.reserve(peers.size());
  for (PartyIndex peer : peers) {
    out.push_back(map.at(peer));
  }
  return out;
}

}  // namespace tecdsa::core::protocol
