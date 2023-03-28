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

#include "yacl/base/exception.h"
#include "yacl/link/factory.h"
#include "yacl/link/transport/channel_brpc.h"

namespace yacl::link {

std::shared_ptr<Context> FactoryBrpc::CreateContext(const ContextDesc& desc,
                                                    size_t self_rank) {
  const size_t world_size = desc.parties.size();
  if (self_rank >= world_size) {
    YACL_THROW_LOGIC_ERROR("invalid self rank={}, world_size={}", self_rank,
                           world_size);
  }

  auto msg_loop = std::make_unique<ReceiverLoopBrpc>();
  std::vector<std::shared_ptr<IChannel>> channels(world_size);
  for (size_t rank = 0; rank < world_size; rank++) {
    if (rank == self_rank) {
      continue;
    }

    ChannelBrpc::Options opts;
    opts.http_timeout_ms = desc.http_timeout_ms;
    opts.http_max_payload_size = desc.http_max_payload_size;
    opts.channel_protocol = desc.brpc_channel_protocol;
    if (!desc.brpc_channel_connection_type.empty()) {
      opts.channel_connection_type = desc.brpc_channel_connection_type;
    }
    auto channel = std::make_shared<ChannelBrpc>(self_rank, rank,
                                                 desc.recv_timeout_ms, opts);
    channel->SetPeerHost(desc.parties[rank].host,
                         desc.enable_ssl ? &desc.client_ssl_opts : nullptr);
    channel->SetThrottleWindowSize(desc.throttle_window_size);

    msg_loop->AddListener(rank, channel);
    channels[rank] = std::move(channel);
  }

  // start receiver loop.
  const auto self_host = desc.parties[self_rank].host;
  msg_loop->Start(self_host, desc.enable_ssl ? &desc.server_ssl_opts : nullptr);

  return std::make_shared<Context>(desc, self_rank, std::move(channels),
                                   std::move(msg_loop));
}

}  // namespace yacl::link
