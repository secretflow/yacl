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

#include "yacl/link/algorithm/allgather.h"

#include "fmt/format.h"

#include "yacl/base/exception.h"
#include "yacl/link/trace.h"
#include "yacl/utils/serialize.h"

namespace yacl::link {
namespace {
const char* kType = "ALLGATHER";
}  // namespace

template <class ValueType>
std::vector<Buffer> AllGatherImpl(const std::shared_ptr<Context>& ctx,
                                  ValueType&& input, std::string_view tag) {
  const auto event = fmt::format("{}:{}", ctx->NextId(), kType);

  TraceLogger::LinkTrace(event, tag, input);

  // broadcast to all
  for (size_t idx = 0; idx < ctx->WorldSize(); idx++) {
    if (idx == ctx->Rank()) {
      continue;
    }

    ctx->SendAsyncInternal(idx, event, input);
  }

  // gather all
  std::vector<Buffer> outputs(ctx->WorldSize());
  for (size_t idx = 0; idx < ctx->WorldSize(); idx++) {
    if (idx == ctx->Rank()) {
      outputs[idx] = Buffer(std::forward<ValueType>(input));
      continue;
    }

    outputs[idx] = ctx->RecvInternal(idx, event);
  }

  return outputs;
}

template <typename ValueType>
std::vector<std::vector<Buffer>> AllGatherVectorImpl(
    const std::shared_ptr<Context>& ctx, ValueType&& inputs,
    std::string_view tag) {
  const auto inputs_size = inputs.size();
  std::vector<std::vector<Buffer>> outputs(inputs_size);
  if (inputs.empty()) {
    return outputs;
  }

  for (size_t idx = 0; idx < inputs_size; idx++) {
    outputs[idx].resize(ctx->WorldSize());
  }

  if (inputs_size == 1) {
    // special path for inputs_size == 1, skip Serialize again.
    std::vector<Buffer> output_buffer;
    if constexpr (std::is_rvalue_reference_v<decltype(inputs)>) {
      output_buffer = AllGatherImpl(ctx, std::move(inputs[0]), tag);
    } else {
      output_buffer = AllGatherImpl(ctx, inputs[0], tag);
    }

    YACL_ENFORCE(output_buffer.size() == ctx->WorldSize());

    for (size_t rank = 0; rank < output_buffer.size(); ++rank) {
      outputs[0][rank] = std::move(output_buffer[rank]);
    }
  } else {
    auto ser_inputs = SerializeArrayOfBuffers({inputs.begin(), inputs.end()});
    if constexpr (std::is_rvalue_reference_v<decltype(inputs)>) {
      inputs.clear();
    }
    std::vector<Buffer> all_outputs_packed =
        AllGatherImpl(ctx, std::move(ser_inputs), tag);

    YACL_ENFORCE(all_outputs_packed.size() == ctx->WorldSize());

    for (size_t rank = 0; rank < all_outputs_packed.size(); ++rank) {
      std::vector<Buffer> outputs_i =
          DeserializeArrayOfBuffers(all_outputs_packed[rank]);
      YACL_ENFORCE(outputs_i.size() == inputs_size);
      all_outputs_packed[rank].reset();

      for (size_t idx = 0; idx < inputs_size; idx++) {
        outputs[idx][rank] = std::move(outputs_i[idx]);
      }
    }
  }

  return outputs;
}

std::vector<Buffer> AllGather(const std::shared_ptr<Context>& ctx,
                              ByteContainerView input, std::string_view tag) {
  return AllGatherImpl(ctx, input, tag);
}

std::vector<std::vector<Buffer>> AllGather(
    const std::shared_ptr<Context>& ctx,
    const std::vector<ByteContainerView>& inputs, std::string_view tag) {
  return AllGatherVectorImpl(ctx, inputs, tag);
}

}  // namespace yacl::link
