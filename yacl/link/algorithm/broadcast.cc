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

#include "yacl/link/algorithm/broadcast.h"

#include "absl/numeric/bits.h"
#include "fmt/format.h"

#include "yacl/base/exception.h"
#include "yacl/link/trace.h"

namespace yacl::link {
namespace {

const char* kType = "BCAST";

size_t RingOffset(size_t begin, size_t end, size_t size) {
  return (end - begin + size) % size;
}

}  // namespace

Buffer Broadcast(const std::shared_ptr<Context>& ctx, ByteContainerView input,
                 size_t root, std::string_view tag) {
  // Binomial tree broadcast impl.
  // see: https://en.wikipedia.org/wiki/Broadcast_(parallel_pattern)
  //
  // |-0-|-1-|-2-|-3-|-4-|-5-| nodes
  // |-A-|---|---|---|---|---| init
  // |-A-|---|---|---|-A-|---| level 1, 0=>4
  // |-A-|---|-B-|---|-A-|---| level 2, 0=>2, (4=>6)
  // |-A-|-C-|-B-|-C-|-A-|-C-| level 3, 0=>1, 2=>3, 4=>5

  const auto event = fmt::format("{}:{}", ctx->NextId(), kType);
  Buffer output = yacl::Buffer(input);

  TraceLogger::LinkTrace(event, tag, input);

  // The algorithm writes in virtual rank space, (which take root as rank 0).
  // But the actual Send/Recv rank is constructed in physical rank space.
  const size_t vrank = RingOffset(root, ctx->Rank(), ctx->WorldSize());
  bool received = (vrank == 0);
  for (size_t stride = absl::bit_floor(ctx->WorldSize()); stride > 0;
       stride >>= 1) {
    if (!received) {
      if (vrank % stride) {
        // waiting for my turn.
        continue;
      }
      output = ctx->RecvInternal(ctx->PrevRank(stride), event);
      received = true;

    } else {
      if (vrank + stride < ctx->WorldSize()) {
        ctx->SendAsyncInternal(ctx->NextRank(stride), event, output);
      }
    }
  }

  return output;
}  // namespace link

}  // namespace yacl::link
