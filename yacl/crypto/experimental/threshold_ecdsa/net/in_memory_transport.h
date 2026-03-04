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

class InMemoryTransport : public ITransport,
                          public std::enable_shared_from_this<InMemoryTransport> {
 public:
  InMemoryTransport(PartyIndex self_id, std::shared_ptr<InMemoryNetwork> network);
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
