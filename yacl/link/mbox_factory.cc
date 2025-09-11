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

#include "yacl/link/mbox_factory.h"

#include <chrono>
#include <exception>
#include <future>
#include <map>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace yacl::link {

InMemoryMbox::InMemoryMbox(
    size_t rank, std::shared_ptr<InMemoryMbox::SharedState> shared_state)
    : rank_(rank), shared_state_(std::move(shared_state)) {}

void InMemoryMbox::Send(size_t dst, std::string_view key,
                        absl::Span<const uint8_t> data) {
  if (dst >= shared_state_->mailboxes.size()) {
    throw std::out_of_range("Destination rank out of range");
  }

  std::vector<uint8_t> data_copy(data.begin(), data.end());
  std::string full_key =
      "/frm/" + std::to_string(rank_) + "/msg/" + std::string(key);

  std::lock_guard<std::mutex> lock(shared_state_->mutex);

  // Store the message in the destination's mailbox
  shared_state_->mailboxes[dst][full_key] = std::move(data_copy);

  shared_state_->cv.notify_all();
}

std::optional<std::vector<uint8_t>> InMemoryMbox::Recv(size_t src,
                                                       std::string_view key,
                                                       int64_t timeout_ms) {
  if (src >= shared_state_->mailboxes.size()) {
    throw std::out_of_range("Source rank out of range");
  }

  std::string full_key =
      "/frm/" + std::to_string(src) + "/msg/" + std::string(key);

  std::optional<std::vector<uint8_t>> result = std::nullopt;

  auto stop_wait = [&] {
    auto& mailbox = shared_state_->mailboxes[rank_];
    auto iter = mailbox.find(full_key);
    if (iter != mailbox.end()) {
      result = std::move(iter->second);
      mailbox.erase(iter);
      return true;
    }
    return false;
  };

  std::unique_lock<std::mutex> lock(shared_state_->mutex);

  shared_state_->cv.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                             stop_wait);
  return result;
}

std::vector<std::shared_ptr<Mbox>> CreateInMemoryMboxs(size_t world_size) {
  std::vector<std::shared_ptr<Mbox>> result;
  result.reserve(world_size);

  // Create a shared state for all mboxes
  auto shared_state = std::make_shared<InMemoryMbox::SharedState>(world_size);

  for (size_t i = 0; i < world_size; ++i) {
    result.emplace_back(std::make_shared<InMemoryMbox>(i, shared_state));
  }

  return result;
}

}  // namespace yacl::link