// Copyright 2025 Ant Group Co., Ltd.
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

#include <map>
#include <optional>
#include <string>
#include <vector>

#include "absl/types/span.h"

namespace yacl::link {

// Mbox is a mailbox for communication.
// It is used to send and receive messages between multiple parties.
class Mbox {
 public:
  virtual ~Mbox() = default;

  // Send a message to the rank `dst` party.
  virtual void Send(size_t dst, std::string_view key,
                    absl::Span<const uint8_t> data) = 0;

  // Receive a message from the rank `src` party.
  virtual std::optional<std::vector<uint8_t>> Recv(size_t src,
                                                   std::string_view key,
                                                   int64_t timeout_ms) = 0;
};

}  // namespace yacl::link