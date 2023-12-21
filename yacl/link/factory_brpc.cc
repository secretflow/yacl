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

#include <memory>

#include "absl/strings/match.h"
#include "butil/logging.h"
#include "gflags/gflags.h"

#include "yacl/base/exception.h"
#include "yacl/link/factory.h"
#include "yacl/link/transport/brpc_link.h"
#include "yacl/link/transport/channel.h"

namespace brpc::policy {
DECLARE_int32(h2_client_stream_window_size);
}

namespace yacl::link {

std::shared_ptr<Context> FactoryBrpc::CreateContext(const ContextDesc& desc,
                                                    size_t self_rank) {
#if !defined(NDEBUG)
  // Under release build, set logging to one level above waring
  logging::SetMinLogLevel(logging::BLOG_WARNING + 1);
#endif
  if (desc.link_type != "normal") {
    return FactoryBrpcBlackBox().CreateContext(desc, self_rank);
  }

  const size_t world_size = desc.parties.size();
  if (self_rank >= world_size) {
    YACL_THROW_LOGIC_ERROR("invalid self rank={}, world_size={}", self_rank,
                           world_size);
  }

  auto opts = transport::BrpcLink::GetDefaultOptions();
  opts = transport::BrpcLink::MakeOptions(
      opts, desc.http_timeout_ms, desc.http_max_payload_size,
      desc.brpc_channel_protocol, desc.brpc_channel_connection_type);

  auto msg_loop = std::make_unique<transport::ReceiverLoopBrpc>();
  std::vector<std::shared_ptr<transport::IChannel>> channels(world_size);
  for (size_t rank = 0; rank < world_size; rank++) {
    if (rank == self_rank) {
      continue;
    }

    auto delegate =
        std::make_shared<transport::BrpcLink>(self_rank, rank, opts);
    delegate->SetPeerHost(desc.parties[rank].host,
                          desc.enable_ssl ? &desc.client_ssl_opts : nullptr);

    auto channel = std::make_shared<transport::Channel>(
        delegate, desc.recv_timeout_ms, desc.exit_if_async_error,
        desc.retry_opts);
    channel->SetThrottleWindowSize(desc.throttle_window_size);
    channel->SetDisableMsgSeqId(desc.disable_msg_seq_id);
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
