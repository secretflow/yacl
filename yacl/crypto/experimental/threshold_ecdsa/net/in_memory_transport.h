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
#include <mutex>
#include <unordered_map>

#include "yacl/crypto/experimental/threshold_ecdsa/net/transport.h"

namespace tecdsa {

class InMemoryTransport;

class InMemoryNetwork : public std::enable_shared_from_this<InMemoryNetwork> {
 public:
  std::shared_ptr<InMemoryTransport> CreateEndpoint(PartyIndex self_id);

 private:
  friend class InMemoryTransport;

  bool Send(const Envelope& envelope, PartyIndex to);
  void Broadcast(const Envelope& envelope, PartyIndex from);
  void Unregister(PartyIndex self_id);

  std::unordered_map<PartyIndex, std::weak_ptr<InMemoryTransport>> endpoints_;
  std::mutex mu_;
};

class InMemoryTransport
    : public ITransport,
      public std::enable_shared_from_this<InMemoryTransport> {
 public:
  InMemoryTransport(PartyIndex self_id,
                    std::shared_ptr<InMemoryNetwork> network);
  ~InMemoryTransport() override;

  InMemoryTransport(const InMemoryTransport&) = delete;
  InMemoryTransport& operator=(const InMemoryTransport&) = delete;

  void Send(PartyIndex to, const Envelope& envelope) override;
  void Broadcast(const Envelope& envelope) override;
  void RegisterHandler(EnvelopeHandler handler) override;

  PartyIndex self_id() const;

 private:
  friend class InMemoryNetwork;
  void Deliver(const Envelope& envelope);

  PartyIndex self_id_;
  std::shared_ptr<InMemoryNetwork> network_;
  std::mutex mu_;
  EnvelopeHandler handler_;
};

}  // namespace tecdsa
