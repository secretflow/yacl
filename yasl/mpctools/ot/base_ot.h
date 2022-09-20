// Copyright 2022 Ant Group Co., Ltd.
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

#include "absl/types/span.h"

#include "yasl/base/int128.h"
#include "yasl/link/link.h"

namespace yasl {

using Block = uint128_t;

void BaseOtRecv(const std::shared_ptr<link::Context>& ctx,
                const std::vector<bool>& choices,
                absl::Span<Block> recv_blocks);

void BaseOtSend(const std::shared_ptr<link::Context>& ctx,
                absl::Span<std::array<Block, 2>> send_blocks);

inline std::vector<Block> BaseOtRecv(const std::shared_ptr<link::Context>& ctx,
                                     const std::vector<bool>& choices) {
  std::vector<Block> blocks(choices.size());
  BaseOtRecv(ctx, choices, absl::MakeSpan(blocks));
  return blocks;
}

inline std::vector<std::array<Block, 2>> BaseOtSend(
    const std::shared_ptr<link::Context>& ctx, size_t num_choice) {
  std::vector<std::array<Block, 2>> blocks(num_choice);
  BaseOtSend(ctx, absl::MakeSpan(blocks));
  return blocks;
}

}  // namespace yasl
