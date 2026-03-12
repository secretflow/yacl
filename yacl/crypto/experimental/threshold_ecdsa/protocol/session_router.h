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
