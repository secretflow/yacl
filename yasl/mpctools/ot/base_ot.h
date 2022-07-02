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
