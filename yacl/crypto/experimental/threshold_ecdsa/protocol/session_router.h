#pragma once

#include <unordered_map>

#include "yacl/crypto/experimental/threshold_ecdsa/net/transport.h"

namespace tecdsa {

class SessionRouter {
 public:
  explicit SessionRouter(PartyIndex self_id);

  void RegisterSession(const Bytes& session_id, EnvelopeHandler handler);
  void UnregisterSession(const Bytes& session_id);

  bool Route(const Envelope& envelope);
  size_t rejected_count() const;

 private:
  static std::string SessionKey(const Bytes& session_id);

  PartyIndex self_id_;
  std::unordered_map<std::string, EnvelopeHandler> handlers_;
  size_t rejected_count_ = 0;
};

}  // namespace tecdsa
