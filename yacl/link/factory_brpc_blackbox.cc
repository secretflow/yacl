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

#include <unistd.h>

#include <iterator>
#include <string_view>

#include "absl/strings/match.h"
#include "absl/strings/str_replace.h"
#include "absl/strings/str_split.h"
#include "gflags/gflags.h"

#include "yacl/base/exception.h"
#include "yacl/link/context.h"
#include "yacl/link/factory.h"
#include "yacl/link/transport/brpc_blackbox_link.h"
#include "yacl/link/transport/brpc_link.h"
#include "yacl/link/transport/channel.h"

namespace brpc::policy {
DECLARE_int32(h2_client_stream_window_size);
}

extern char** environ;

namespace yacl::link {

void FactoryBrpcBlackBox::GetPartyNodeInfoFromEnv(
    std::vector<ContextDesc::Party>& parties, size_t& self_rank) {
  static constexpr std::string_view kNodeInfoPrefix = "config.node_id.";
  static constexpr std::string_view kSelfPartyKey = "config.self_role";
  YACL_ENFORCE(environ != nullptr, "environ is null");
  std::map<std::string, std::string> party_info;
  std::string self_party_id;
  for (char** env = environ; *env != nullptr; ++env) {
    std::vector<std::string> k_v = absl::StrSplit(*env, '=');
    if (absl::StartsWith(k_v[0], kNodeInfoPrefix)) {
      YACL_ENFORCE(k_v.size() == 2, "{} format error: should be A=B",
                   std::string(*env));
      auto party_id = absl::StrReplaceAll(k_v[0], {{"config.node_id.", ""}});
      YACL_ENFORCE(party_info.find(party_id) == party_info.end(),
                   "party id: {} is duplicated.", party_id);
      party_info[party_id] = k_v[1];
    } else if (absl::StartsWith(k_v[0], kSelfPartyKey)) {
      YACL_ENFORCE(k_v.size() == 2, "{} format error: should be A=B",
                   std::string(*env));
      YACL_ENFORCE(self_party_id.empty(),
                   "config.self_role should appear only once");
      self_party_id = k_v[1];
    }
  }
  auto iter = party_info.find(self_party_id);
  YACL_ENFORCE(iter != party_info.end(), "cannot find {}:{} in ENV({}*)",
               kSelfPartyKey, self_party_id, kNodeInfoPrefix);
  self_rank = std::distance(party_info.begin(), iter);
  for (auto const& [party_id, node_id] : party_info) {
    parties.emplace_back(ContextDesc::Party(party_id, node_id));
  }
}

std::shared_ptr<Context> FactoryBrpcBlackBox::CreateContext(
    const ContextDesc& desc, size_t self_rank) {
  const size_t world_size = desc.parties.size();
  if (self_rank >= world_size) {
    YACL_THROW_LOGIC_ERROR("invalid self rank={}, world_size={}", self_rank,
                           world_size);
  }
  auto options = transport::BrpcBlackBoxLink::GetDefaultOptions();
  options = transport::BrpcBlackBoxLink::MakeOptions(
      options, desc.http_timeout_ms, desc.http_max_payload_size,
      desc.brpc_channel_protocol, desc.brpc_channel_connection_type);

  if (options.channel_protocol != "http" && options.channel_protocol != "h2") {
    YACL_THROW_LOGIC_ERROR(
        "invalid protocol: {}, blackbox protocol should be http",
        options.channel_protocol);
  }

  auto msg_loop = std::make_unique<transport::ReceiverLoopBlackBox>();
  std::vector<std::shared_ptr<transport::IChannel>> channels(world_size);
  for (size_t rank = 0; rank < world_size; rank++) {
    if (rank == self_rank) {
      continue;
    }

    auto delegate =
        std::make_shared<transport::BrpcBlackBoxLink>(self_rank, rank, options);
    delegate->SetPeerHost(desc.parties[self_rank].id,
                          desc.parties[self_rank].host, desc.parties[rank].id,
                          desc.parties[rank].host,
                          desc.enable_ssl ? &desc.client_ssl_opts : nullptr);

    auto channel = std::make_shared<transport::Channel>(
        delegate, desc.recv_timeout_ms, false, desc.retry_opts);
    channel->SetThrottleWindowSize(desc.throttle_window_size);
    msg_loop->AddLinkAndChannel(rank, channel, delegate);

    channels[rank] = std::move(channel);
  }

  // start receiver loop.
  msg_loop->Start();

  return std::make_shared<Context>(desc, self_rank, std::move(channels),
                                   std::move(msg_loop));
}

}  // namespace yacl::link
