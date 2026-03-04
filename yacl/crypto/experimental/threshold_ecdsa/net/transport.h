#pragma once

#include <functional>

#include "yacl/crypto/experimental/threshold_ecdsa/net/envelope.h"

namespace tecdsa {

using EnvelopeHandler = std::function<void(const Envelope& envelope)>;

class ITransport {
 public:
  virtual ~ITransport() = default;

  virtual void Send(PartyIndex to, const Envelope& envelope) = 0;
  virtual void Broadcast(const Envelope& envelope) = 0;

  virtual void RegisterHandler(EnvelopeHandler handler) = 0;
};

}  // namespace tecdsa
