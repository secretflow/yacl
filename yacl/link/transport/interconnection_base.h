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

namespace org::interconnection::link {
class PushRequest;
class PushResponse;
}  // namespace org::interconnection::link

namespace yacl::link::transport {

class InterconnectionBase : public ChannelBase {
 public:
  struct Options {
    uint32_t http_timeout_ms;        // 10 seconds
    uint32_t http_max_payload_size;  // 512k bytes
    std::string channel_protocol;
    std::string channel_connection_type;

    Options() = delete;
    Options(uint32_t http_timeout, uint32_t http_max_payload,
            std::string protocol, std::string connection_type)
        : http_timeout_ms(http_timeout),
          http_max_payload_size(http_max_payload),
          channel_protocol(std::move(protocol)),
          channel_connection_type(std::move(connection_type)) {}
  };
  static auto MakeOptions(Options& default_opt, uint32_t http_timeout_ms,
                          uint32_t http_max_payload_size,
                          const std::string& brpc_channel_protocol,
                          const std::string& brpc_channel_connection_type)
      -> Options;

 private:
  // from IChannel
  void SendImpl(const std::string& key, ByteContainerView value) override;
  void SendImpl(const std::string& key, ByteContainerView value,
                uint32_t timeout) override;

  // send chunked, synchronized.
  void SendChunked(const std::string& key, ByteContainerView value);

 public:
  InterconnectionBase(size_t self_rank, size_t peer_rank, Options options,
                      bool exit_if_async_error = true)
      : ChannelBase(self_rank, peer_rank, exit_if_async_error),
        options_(std::move(options)) {}

  InterconnectionBase(size_t self_rank, size_t peer_rank,
                      size_t recv_timeout_ms, Options options,
                      bool exit_if_async_error = true)
      : ChannelBase(self_rank, peer_rank, recv_timeout_ms, exit_if_async_error),
        options_(std::move(options)) {}

  virtual void PushRequest(org::interconnection::link::PushRequest& request,
                           uint32_t timeout) = 0;

  // max payload size for a single http request, in bytes.
  uint32_t GetHttpMaxPayloadSize() const {
    return options_.http_max_payload_size;
  }

  void SetHttpMaxPayloadSize(uint32_t max_payload_size) {
    options_.http_max_payload_size = max_payload_size;
  }

  void OnRequest(const ::org::interconnection::link::PushRequest* request,
                 ::org::interconnection::link::PushResponse* response);

 protected:
  Options options_;
};

}  // namespace yacl::link::transport
