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

#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

#include "yacl/link/transport/channel.h"

namespace yacl::link::transport {

class ReceiverLoopMem final : public IReceiverLoop {
 public:
  ~ReceiverLoopMem() override = default;

  // do nothing, mem channel does't not have a loop thread.
  void Stop() override {}
};

class ChannelMem final : public IChannel {
 public:
  ~ChannelMem() override {
    if (!finished_) {
      // WaitLinkTaskFinish should be called if you want to keep sync with
      // peers.
    }
  }

  ChannelMem(size_t self_rank, size_t peer_rank, size_t timeout_ms = 20000U);

  void SetPeer(const std::shared_ptr<ChannelMem>& peer_task);

  void SendAsync(const std::string& key, ByteContainerView value) final {
    SendImpl(key, value);
  }

  void SendAsync(const std::string& key, Buffer&& value) final {
    SendImpl(key, value);
  }

  void SendAsyncThrottled(const std::string& key, Buffer&& value) final {
    SendImpl(key, value);
  }

  void SendAsyncThrottled(const std::string& key,
                          ByteContainerView value) final {
    SendImpl(key, value);
  }

  void Send(const std::string& key, ByteContainerView value) final {
    SendImpl(key, value);
  }

  Buffer Recv(const std::string& key) final;

  void OnMessage(const std::string& key, ByteContainerView value) final;

  void SetRecvTimeout(uint64_t timeout_ms) final {
    recv_timeout_ms_ = timeout_ms * std::chrono::milliseconds(1);
  }

  uint64_t GetRecvTimeout() const final { return recv_timeout_ms_.count(); }

  void WaitLinkTaskFinish() final;

  void Abort() override { YACL_THROW("not supported yet"); }

  // do nothing
  void SetThrottleWindowSize(size_t) final {}
  void TestSend(uint32_t /*timeout*/) final {}
  void TestRecv() final {}
  void SetChunkParallelSendSize(size_t) final {}
  // no affect

 private:
  void SendImpl(const std::string& key, ByteContainerView value);
  // Note: we should never manage peer's lifetime.
  std::weak_ptr<ChannelMem> peer_channel_;
  // message database related.
  std::mutex msg_mutex_;
  std::condition_variable msg_db_cond_;
  std::unordered_map<std::string, Buffer> recv_msgs_;

  std::chrono::milliseconds recv_timeout_ms_ =
      3UL * 60 * std::chrono::milliseconds(1000);

  std::atomic<bool> finished_{true};
  inline static const std::string kFinKey = "_fin_";
};

}  // namespace yacl::link::transport
