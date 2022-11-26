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

#include "yacl/link/algorithm/barrier.h"

#include "fmt/format.h"

#include "yacl/base/byte_container_view.h"
#include "yacl/link/trace.h"

namespace yacl::link {
namespace {
const char* kType = "BARRIER";
}  // namespace

void Barrier(const std::shared_ptr<Context>& ctx, std::string_view tag) {
  const auto event = fmt::format("{}:{}", ctx->NextId(), kType);

  TraceLogger::LinkTrace(event, tag, "");

  // Rounds: ceil(log(n))
  // See: https://www.inf.ed.ac.uk/teaching/courses/ppls/BarrierPaper.pdf
  for (size_t offset = 1; offset < ctx->WorldSize(); offset <<= 1) {
    const size_t recv_rank = ctx->PrevRank(offset);
    const size_t send_rank = ctx->NextRank(offset);
    ctx->SendAsyncInternal(send_rank, event, ByteContainerView{});
    ctx->RecvInternal(recv_rank, event);
  }
}

}  // namespace yacl::link
