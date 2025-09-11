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

#include <condition_variable>
#include <mutex>

#include "yacl/link/mbox.h"

namespace yacl::link {

class InMemoryMbox : public Mbox {
 public:
  struct SharedState;
  InMemoryMbox(size_t rank, std::shared_ptr<SharedState> shared_state);

  void Send(size_t dst, std::string_view key,
            absl::Span<const uint8_t> data) override;

  std::optional<std::vector<uint8_t>> Recv(size_t src, std::string_view key,
                                           int64_t timeout_ms) override;

 public:
  struct SharedState {
    explicit SharedState(size_t world_size) : mailboxes(world_size) {}

    std::mutex mutex;
    std::condition_variable cv;
    std::vector<std::map<std::string, std::vector<uint8_t>>> mailboxes;
  };

 private:
  size_t rank_;
  std::shared_ptr<SharedState> shared_state_;
};

// Factory function to create in-memory mboxs for testing.
// The returned mboxs size is `world_size`, and each mbox is assigned a rank
// from 0 to world_size - 1.
std::vector<std::shared_ptr<Mbox>> CreateInMemoryMboxs(size_t world_size);

}  // namespace yacl::link