#pragma once

#include "absl/types/span.h"

#include "yasl/base/int128.h"
#include "yasl/link/link.h"

namespace yasl {

using Block = uint128_t;

class BaseOTInterface {
 public:
  virtual ~BaseOTInterface();
  virtual void Send(const std::shared_ptr<link::Context>& ctx,
                    absl::Span<std::array<Block, 2>> send_blocks) = 0;
  virtual void Recv(const std::shared_ptr<link::Context>& ctx,
                    const std::vector<bool>& choices,
                    absl::Span<Block> recv_blocks) = 0;
};

}  // namespace yasl
