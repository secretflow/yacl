// Copyright 2019 Ant Group Co., Ltd.
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

#include "yacl/link/transport/channel_mem.h"

#include "yacl/base/exception.h"

namespace yacl::link::transport {

ChannelMem::ChannelMem(size_t /*self_rank*/, size_t /*peer_rank*/,
                       size_t timeout_ms)
    : recv_timeout_ms_(timeout_ms * std::chrono::milliseconds(1)) {}

void ChannelMem::SetPeer(const std::shared_ptr<ChannelMem>& peer_task) {
  peer_channel_ = peer_task;
  finished_ = false;
}

void ChannelMem::SendImpl(const std::string& key, ByteContainerView value) {
  if (auto ptr = peer_channel_.lock()) {
    ptr->OnMessage(key, value);
  } else {
    YACL_THROW_IO_ERROR("Peer's memory channel released");
  }
}

Buffer ChannelMem::Recv(const std::string& key) {
  Buffer value;
  {
    std::unique_lock lock(msg_mutex_);
    auto stop_waiting = [&] {
      auto itr = this->recv_msgs_.find(key);
      if (itr == this->recv_msgs_.end()) {
        return false;
      } else {
        value = std::move(itr->second);
        this->recv_msgs_.erase(itr);
        return true;
      }
    };
    if (!msg_db_cond_.wait_for(lock, recv_timeout_ms_, stop_waiting)) {
      YACL_THROW_IO_ERROR("Get data timeout, key={}", key);
    }
  }

  return value;
}

void ChannelMem::OnMessage(const std::string& msg_key,
                           ByteContainerView value) {
  {
    std::unique_lock lock(msg_mutex_);
    recv_msgs_.emplace(msg_key, value);
  }
  msg_db_cond_.notify_all();
}

void ChannelMem::WaitLinkTaskFinish() {
  bool expect = false;
  if (!finished_.compare_exchange_strong(expect, true)) {
    return;
  }

  SendImpl(kFinKey, "");
  auto recv = Recv(kFinKey);
  recv.reset();
  finished_ = true;
}

}  // namespace yacl::link::transport
