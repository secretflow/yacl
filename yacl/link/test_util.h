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

#include <future>
#include <vector>

#include "fmt/format.h"

#include "yacl/base/buffer.h"
#include "yacl/link/context.h"
#include "yacl/link/factory.h"

namespace yacl::link::test {

inline std::vector<std::shared_ptr<Context>> SetupBrpcWorld(
    const std::string& id, size_t world_size) {
  ContextDesc ctx_desc;
  // ctx_desc.id = id;
  for (size_t rank = 0; rank < world_size; rank++) {
    const auto party_id = fmt::format("{}-{}", id, rank);
    const auto host = fmt::format("127.0.0.1:{}", 10086 + rank);
    ctx_desc.parties.push_back({party_id, host});
  }

  std::vector<std::shared_ptr<Context>> contexts(world_size);
  for (size_t rank = 0; rank < world_size; rank++) {
    contexts[rank] = FactoryBrpc().CreateContext(ctx_desc, rank);
  }

  auto proc = [&](size_t rank) {
    contexts[rank]->ConnectToMesh();
    // If throttle_window_size is not zero, "SendAsync" will block until
    // messages are processed
    contexts[rank]->SetThrottleWindowSize(0);
  };
  std::vector<std::future<void>> jobs(world_size);
  for (size_t rank = 0; rank < world_size; rank++) {
    jobs[rank] = std::async(proc, rank);
  }

  for (size_t rank = 0; rank < world_size; rank++) {
    jobs[rank].get();
  }
  return contexts;
}

inline std::vector<std::shared_ptr<Context>> SetupBrpcWorld(size_t world_size) {
  auto id = fmt::format("world_{}", world_size);
  return SetupBrpcWorld(id, world_size);
}

inline std::vector<std::shared_ptr<Context>> SetupWorld(const std::string& id,
                                                        size_t world_size) {
  ContextDesc ctx_desc;
  ctx_desc.id = id;
  for (size_t rank = 0; rank < world_size; rank++) {
    ctx_desc.parties.push_back(
        {fmt::format("dummy_id:{}", rank), "dummy_host"});
  }

  std::vector<std::shared_ptr<Context>> contexts(world_size);
  for (size_t rank = 0; rank < world_size; rank++) {
    contexts[rank] = FactoryMem().CreateContext(ctx_desc, rank);
  }

  auto proc = [&](size_t rank) { contexts[rank]->ConnectToMesh(); };
  std::vector<std::future<void>> jobs(world_size);
  for (size_t rank = 0; rank < world_size; rank++) {
    jobs[rank] = std::async(proc, rank);
  }

  for (size_t rank = 0; rank < world_size; rank++) {
    jobs[rank].get();
  }
  return contexts;
}

inline std::vector<std::shared_ptr<Context>> SetupWorld(size_t world_size) {
  auto id = fmt::format("world_{}", world_size);
  return SetupWorld(id, world_size);
}

inline std::string MakeRoundData(size_t rank, size_t round) {
  // result in different content/length for each rank/round.
  const auto spaces = std::string(rank, '_');
  return fmt::format("d:{},{},r:{}", rank, spaces, round);
}

}  // namespace yacl::link::test
