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

#include "yacl/crypto/experimental/threshold_ecdsa/net/in_memory_transport.h"

#include <stdexcept>
#include <vector>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"

namespace tecdsa {

std::shared_ptr<InMemoryTransport> InMemoryNetwork::CreateEndpoint(
    PartyIndex self_id) {
  if (self_id == 0) {
    TECDSA_THROW_ARGUMENT("InMemory endpoint self_id must be non-zero");
  }

  auto endpoint = std::shared_ptr<InMemoryTransport>(
      new InMemoryTransport(self_id, shared_from_this()));

  std::lock_guard<std::mutex> lock(mu_);
  endpoints_[self_id] = endpoint;
  return endpoint;
}

bool InMemoryNetwork::Send(const Envelope& envelope, PartyIndex to) {
  std::shared_ptr<InMemoryTransport> target;
  {
    std::lock_guard<std::mutex> lock(mu_);
    const auto it = endpoints_.find(to);
    if (it == endpoints_.end()) {
      return false;
    }
    target = it->second.lock();
    if (!target) {
      endpoints_.erase(it);
      return false;
    }
  }

  target->Deliver(envelope);
  return true;
}

void InMemoryNetwork::Broadcast(const Envelope& envelope, PartyIndex from) {
  std::vector<std::shared_ptr<InMemoryTransport>> targets;
  {
    std::lock_guard<std::mutex> lock(mu_);
    for (auto it = endpoints_.begin(); it != endpoints_.end();) {
      auto endpoint = it->second.lock();
      if (!endpoint) {
        it = endpoints_.erase(it);
        continue;
      }

      if (it->first != from) {
        targets.push_back(std::move(endpoint));
      }
      ++it;
    }
  }

  for (const auto& target : targets) {
    target->Deliver(envelope);
  }
}

void InMemoryNetwork::Unregister(PartyIndex self_id) {
  std::lock_guard<std::mutex> lock(mu_);
  endpoints_.erase(self_id);
}

InMemoryTransport::InMemoryTransport(PartyIndex self_id,
                                     std::shared_ptr<InMemoryNetwork> network)
    : self_id_(self_id), network_(std::move(network)) {
  if (self_id_ == 0) {
    TECDSA_THROW_ARGUMENT("InMemoryTransport self_id must be non-zero");
  }
  if (!network_) {
    TECDSA_THROW_ARGUMENT("InMemoryTransport requires a network");
  }
}

InMemoryTransport::~InMemoryTransport() {
  if (network_) {
    network_->Unregister(self_id_);
  }
}

void InMemoryTransport::Send(PartyIndex to, const Envelope& envelope) {
  if (envelope.from != self_id_) {
    TECDSA_THROW_ARGUMENT("Envelope.from must match transport self_id");
  }

  Envelope outbound = envelope;
  outbound.to = to;
  if (!network_->Send(outbound, to)) {
    TECDSA_THROW("Send target not found");
  }
}

void InMemoryTransport::Broadcast(const Envelope& envelope) {
  if (envelope.from != self_id_) {
    TECDSA_THROW_ARGUMENT("Envelope.from must match transport self_id");
  }

  Envelope outbound = envelope;
  outbound.to = kBroadcastPartyId;
  network_->Broadcast(outbound, self_id_);
}

void InMemoryTransport::RegisterHandler(EnvelopeHandler handler) {
  std::lock_guard<std::mutex> lock(mu_);
  handler_ = std::move(handler);
}

PartyIndex InMemoryTransport::self_id() const { return self_id_; }

void InMemoryTransport::Deliver(const Envelope& envelope) {
  EnvelopeHandler handler;
  {
    std::lock_guard<std::mutex> lock(mu_);
    handler = handler_;
  }

  if (handler) {
    handler(envelope);
  }
}

}  // namespace tecdsa
