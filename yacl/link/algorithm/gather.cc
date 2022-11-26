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

#include "yacl/link/algorithm/gather.h"

#include "fmt/format.h"

#include "yacl/base/exception.h"
#include "yacl/link/trace.h"
#include "yacl/utils/serialize.h"

namespace yacl::link {
namespace {
const char* kType = "GATHER";
}  // namespace

template <typename ValueType>
std::vector<Buffer> GatherImpl(const std::shared_ptr<Context>& ctx,
                               ValueType&& input, size_t root,
                               std::string_view tag) {
  const auto event = fmt::format("{}:{}", ctx->NextId(), kType);
  TraceLogger::LinkTrace(event, tag, input);

  std::vector<Buffer> res;

  if (root == ctx->Rank()) {
    res.resize(ctx->WorldSize());
    for (size_t idx = 0; idx < ctx->WorldSize(); idx++) {
      if (idx == ctx->Rank()) {
        res[idx] = Buffer(std::forward<ValueType>(input));
      } else {
        res[idx] = ctx->RecvInternal(idx, event);
      }
    }
  } else {
    ctx->SendAsyncInternal(root, event, std::forward<ValueType>(input));
  }

  return res;
}

template <typename ValueType>
std::vector<std::vector<Buffer>> GatherVectorImpl(
    const std::shared_ptr<Context>& ctx, ValueType&& inputs, size_t root,
    std::string_view tag) {
  const auto inputs_size = inputs.size();
  std::vector<std::vector<Buffer>> outputs(inputs_size);
  if (inputs.empty()) {
    return outputs;
  }

  if (root == ctx->Rank()) {
    for (size_t idx = 0; idx < inputs.size(); idx++) {
      outputs[idx].resize(ctx->WorldSize());
    }
  }

  if (inputs_size == 1) {
    // special path for inputs_size == 1, skip Serialize again.
    std::vector<Buffer> output_buffer;
    if constexpr (std::is_rvalue_reference_v<decltype(inputs)>) {
      output_buffer = GatherImpl(ctx, std::move(inputs[0]), root, tag);
    } else {
      output_buffer = GatherImpl(ctx, inputs[0], root, tag);
    }

    if (root == ctx->Rank()) {
      YACL_ENFORCE(output_buffer.size() == ctx->WorldSize());

      for (size_t rank = 0; rank < output_buffer.size(); ++rank) {
        outputs[0][rank] = std::move(output_buffer[rank]);
      }
    } else {
      YACL_ENFORCE(output_buffer.empty());
    }
  } else {
    auto ser_inputs = SerializeArrayOfBuffers({inputs.begin(), inputs.end()});
    if constexpr (std::is_rvalue_reference_v<decltype(inputs)>) {
      inputs.clear();
    }
    std::vector<Buffer> all_outputs_packed =
        GatherImpl(ctx, std::move(ser_inputs), root, tag);

    if (root == ctx->Rank()) {
      YACL_ENFORCE(all_outputs_packed.size() == ctx->WorldSize());

      for (size_t idx = 0; idx < inputs_size; idx++) {
        outputs[idx].resize(ctx->WorldSize());
      }

      for (size_t rank = 0; rank < all_outputs_packed.size(); ++rank) {
        std::vector<Buffer> outputs_i =
            DeserializeArrayOfBuffers(all_outputs_packed[rank]);
        YACL_ENFORCE(outputs_i.size() == inputs_size);

        for (size_t idx = 0; idx < inputs_size; idx++) {
          outputs[idx][rank] = std::move(outputs_i[idx]);
        }
      }
    } else {
      YACL_ENFORCE(all_outputs_packed.empty());
    }
  }

  return outputs;
}

std::vector<Buffer> Gather(const std::shared_ptr<Context>& ctx,
                           ByteContainerView input, size_t root,
                           std::string_view tag) {
  return GatherImpl(ctx, input, root, tag);
}

std::vector<std::vector<Buffer>> Gather(
    const std::shared_ptr<Context>& ctx,
    const std::vector<ByteContainerView>& inputs, size_t root,
    std::string_view tag) {
  return GatherVectorImpl(ctx, inputs, root, tag);
}

}  // namespace yacl::link
