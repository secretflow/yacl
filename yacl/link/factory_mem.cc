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

#include <future>
#include <unordered_map>

#include "spdlog/spdlog.h"

#include "yacl/base/exception.h"
#include "yacl/link/factory.h"
#include "yacl/link/transport/channel_mem.h"

namespace yacl::link {
namespace {

struct MemSession {
  std::string id;
  std::vector<std::shared_ptr<Context>> ctxs;

  MemSession(std::string _id, std::vector<std::shared_ptr<Context>> _ctxs)
      : id(std::move(_id)), ctxs(std::move(_ctxs)) {}

  ~MemSession() = default;
};

std::mutex _mutex;
std::unordered_map<ContextDesc, std::shared_ptr<MemSession>, ContextDescHasher>
    _sessions;

std::shared_ptr<MemSession> CreateSession(const ContextDesc& desc) {
  const size_t world_size = desc.parties.size();
  std::vector<std::vector<std::shared_ptr<transport::ChannelMem>>> all_channels(
      world_size);
  {
    // create instances.
    for (size_t self_rank = 0; self_rank < world_size; self_rank++) {
      auto& channels = all_channels[self_rank];
      channels.resize(world_size);
      for (size_t peer_rank = 0; peer_rank < world_size; peer_rank++) {
        if (self_rank == peer_rank) {
          continue;
        }
        channels[peer_rank] = std::make_shared<transport::ChannelMem>(
            self_rank, peer_rank, desc.recv_timeout_ms);
      }
    }

    // link references.
    for (size_t self_rank = 0; self_rank < world_size; self_rank++) {
      for (size_t peer_rank = 0; peer_rank < world_size; peer_rank++) {
        if (self_rank == peer_rank) {
          continue;
        }
        all_channels[self_rank][peer_rank]->SetPeer(
            all_channels[peer_rank][self_rank]);
      }
    }
  }

  // setup rendezvous
  std::vector<std::shared_ptr<Context>> ctxs(world_size);
  for (size_t self_rank = 0; self_rank < world_size; self_rank++) {
    std::vector<std::shared_ptr<transport::IChannel>> channels(world_size);
    for (size_t peer_rank = 0; peer_rank < world_size; peer_rank++) {
      channels[peer_rank] = all_channels[self_rank][peer_rank];
    }
    auto msg_loop = std::make_unique<transport::ReceiverLoopMem>();
    ctxs[self_rank] = std::make_shared<Context>(
        desc, self_rank, std::move(channels), std::move(msg_loop));
  }

  return std::make_shared<MemSession>(desc.id, std::move(ctxs));
}

std::shared_ptr<MemSession> CreateOrGetSession(const ContextDesc& desc) {
  std::unique_lock lock(_mutex);
  const auto& itr = _sessions.find(desc);
  if (itr == _sessions.end()) {
    auto session = CreateSession(desc);
    _sessions.emplace(desc, session);
    return session;
  } else {
    return itr->second;
  }
}

}  // namespace

std::shared_ptr<Context> FactoryMem::CreateContext(const ContextDesc& desc,
                                                   size_t rank) {
  if (rank >= desc.parties.size()) {
    YACL_THROW_LOGIC_ERROR("rank={} out of range={}", rank,
                           desc.parties.size());
  }
  auto session = CreateOrGetSession(desc);
  return session->ctxs[rank];
}

}  // namespace yacl::link
