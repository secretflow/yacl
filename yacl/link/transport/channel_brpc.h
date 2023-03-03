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

namespace yacl::link {

class ReceiverLoopBrpc final : public ReceiverLoopBase {
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

 protected:
  brpc::Server server_;

 private:
  void StopImpl();
};

class ChannelBrpc final : public ChannelBase,
                          public std::enable_shared_from_this<ChannelBrpc> {
 public:
  struct Options {
    uint32_t http_timeout_ms = 10 * 1000;         // 10 seconds
    uint32_t http_max_payload_size = 512 * 1024;  // 512k bytes
    std::string channel_protocol = "baidu_std";
    std::string channel_connection_type = "single";
  };

 private:
  // from IChannel
  void SendAsyncImpl(const std::string& key, ByteContainerView value) override;
  void SendAsyncImpl(const std::string& key, Buffer&& value) override;

  void SendImpl(const std::string& key, ByteContainerView value) override;
  void SendImpl(const std::string& key, ByteContainerView value,
                uint32_t timeout) override;

 public:
  ChannelBrpc(size_t self_rank, size_t peer_rank, Options options)
      : ChannelBase(self_rank, peer_rank), options_(std::move(options)) {}

  ChannelBrpc(size_t self_rank, size_t peer_rank, size_t recv_timeout_ms,
              Options options)
      : ChannelBase(self_rank, peer_rank, recv_timeout_ms),
        options_(std::move(options)) {}

  void SetPeerHost(const std::string& peer_host,
                   const SSLOptions* ssl_opts = nullptr);

  void AddAsyncCount();

  void SubAsyncCount();

  void WaitAsyncSendToFinish() override;

  // max payload size for a single http request, in bytes.
  uint32_t GetHttpMaxPayloadSize() const {
    return options_.http_max_payload_size;
  }

  void SetHttpMaxPayloadSize(uint32_t max_payload_size) {
    options_.http_max_payload_size = max_payload_size;
  }

  // send chunked, synchronized.
  void SendChunked(const std::string& key, ByteContainerView value);

 private:
  template <class ValueType>
  void SendAsyncInternal(const std::string& key, ValueType&& value);

 protected:
  Options options_;

  // brpc channel related.
  std::string peer_host_;
  std::shared_ptr<brpc::Channel> channel_;

  // WaitAsyncSendToFinish
  bthread::ConditionVariable wait_async_cv_;
  bthread::Mutex wait_async_mutex_;
  int64_t running_async_count_ = 0;
};

}  // namespace yacl::link
