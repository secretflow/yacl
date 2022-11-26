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

#include "yacl/link/algorithm/scatter.h"

#include "fmt/format.h"

#include "yacl/base/exception.h"
#include "yacl/link/trace.h"

namespace yacl::link {
namespace {
const char* kType = "SCATTER";
}  // namespace

Buffer Scatter(const std::shared_ptr<Context>& ctx,
               const std::vector<ByteContainerView>& inputs, size_t root,
               std::string_view tag) {
  const auto event = fmt::format("{}:{}", ctx->NextId(), kType);

  // TODO: record scatter inputs.
  TraceLogger::LinkTrace(event, tag, "");

  if (root == ctx->Rank()) {
    YACL_ENFORCE(inputs.size() == ctx->WorldSize(),
                 "number of input={} does not match world_size={}",
                 inputs.size(), ctx->WorldSize());

    for (size_t idx = 0; idx < ctx->WorldSize(); idx++) {
      if (idx == ctx->Rank()) {
        continue;
      }

      ctx->SendAsyncInternal(idx, event, inputs[idx]);
    }

    return yacl::Buffer(inputs[root]);
  }
  return ctx->RecvInternal(root, event);
}

}  // namespace yacl::link
