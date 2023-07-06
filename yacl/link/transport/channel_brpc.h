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
#include <utility>

#include "brpc/channel.h"
#include "brpc/server.h"
#include "bthread/bthread.h"
#include "bthread/condition_variable.h"

#include "yacl/link/ssl_options.h"
#include "yacl/link/transport/channel.h"
#include "yacl/link/transport/channel_chunked_base.h"

namespace yacl::link {

class ReceiverLoopBrpc final : public IReceiverLoop {
 public:
  ~ReceiverLoopBrpc() override;

  void Stop() override;

  // start the receiver loop.
  // message received from peers will be listened and dispatched by this loop.
  //
  // host: the desired listen addr:port pair.
  // ssl_opts: ssl related options.
  // returns: the actual listening addr:port pair.
  //
  // Note: brpc support "ip:0" listen mode, in which brpc will try to find a
  // free port to listen.
  std::string Start(const std::string& host,
                    const SSLOptions* ssl_opts = nullptr);

  void AddListener(size_t rank, std::shared_ptr<ChannelChunkedBase> listener) {
    auto ret = listeners_.emplace(rank, std::move(listener));
    if (!ret.second) {
      YACL_THROW_LOGIC_ERROR("duplicated listener for rank={}", rank);
    }
  }

 protected:
  std::map<size_t, std::shared_ptr<ChannelChunkedBase>> listeners_;
  brpc::Server server_;

 private:
  void StopImpl();
};

class ChannelBrpc final : public ChannelChunkedBase {
 public:
  using ChannelChunkedBase::ChannelChunkedBase;

  static ChannelChunkedBase::Options GetDefaultOptions() {
    return ChannelChunkedBase::Options{10 * 1000, 512 * 1024, "baidu_std",
                                       "single"};
  }

  // from IChannel
  void PushRequest(org::interconnection::link::PushRequest& request,
                   uint32_t timeout) override;

  void SetPeerHost(const std::string& peer_host,
                   const SSLOptions* ssl_opts = nullptr);

 protected:
  // brpc channel related.
  std::string peer_host_;
  std::shared_ptr<brpc::Channel> channel_;
};

}  // namespace yacl::link
