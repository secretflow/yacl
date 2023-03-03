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

#include <condition_variable>
#include <memory>
#include <mutex>

#include "yacl/link/transport/channel.h"

namespace yacl::link {

class ReceiverLoopMem final : public ReceiverLoopBase {
 public:
  ~ReceiverLoopMem() override = default;

  // do nothing, mem channel does't not have a loop thread.
  void Stop() override {}
};

class ChannelMem final : public ChannelBase {
 private:
  void SendAsyncImpl(const std::string& key, ByteContainerView value) override;
  void SendAsyncImpl(const std::string& key, Buffer&& value) override;

  void SendImpl(const std::string& key, ByteContainerView value) override;
  void SendImpl(const std::string& key, ByteContainerView value,
                uint32_t /* timeout */) override;

 public:
  ~ChannelMem() override = default;

  ChannelMem(size_t self_rank, size_t peer_rank, size_t timeout_ms = 20000U);

  void SetPeer(const std::shared_ptr<ChannelMem>& peer_task);

  void WaitAsyncSendToFinish() override {}

 protected:
  // Note: we should never manage peer's lifetime.
  std::weak_ptr<ChannelMem> peer_channel_;
};

}  // namespace yacl::link
