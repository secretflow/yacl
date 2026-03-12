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

#include "yacl/crypto/experimental/threshold_ecdsa/protocol/session_router.h"

#include <stdexcept>
#include <utility>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"
#include "yacl/crypto/experimental/threshold_ecdsa/net/envelope.h"

namespace tecdsa {

SessionRouter::SessionRouter(PartyIndex self_id) : self_id_(self_id) {
  if (self_id_ == 0) {
    TECDSA_THROW_ARGUMENT("SessionRouter self_id must be non-zero");
  }
}

void SessionRouter::RegisterSession(const Bytes& session_id,
                                    EnvelopeHandler handler) {
  if (session_id.empty()) {
    TECDSA_THROW_ARGUMENT("session_id must not be empty");
  }
  if (!handler) {
    TECDSA_THROW_ARGUMENT("handler must not be empty");
  }

  handlers_[SessionKey(session_id)] = std::move(handler);
}

void SessionRouter::UnregisterSession(const Bytes& session_id) {
  handlers_.erase(SessionKey(session_id));
}

bool SessionRouter::Route(const Envelope& envelope) {
  if (envelope.session_id.empty()) {
    ++rejected_count_;
    return false;
  }
  if (envelope.type == 0) {
    ++rejected_count_;
    return false;
  }
  if (envelope.to != self_id_ && envelope.to != kBroadcastPartyId) {
    ++rejected_count_;
    return false;
  }

  const auto it = handlers_.find(SessionKey(envelope.session_id));
  if (it == handlers_.end()) {
    ++rejected_count_;
    return false;
  }

  it->second(envelope);
  return true;
}

size_t SessionRouter::rejected_count() const { return rejected_count_; }

std::string SessionRouter::SessionKey(const Bytes& session_id) {
  return std::string(reinterpret_cast<const char*>(session_id.data()),
                     session_id.size());
}

}  // namespace tecdsa
