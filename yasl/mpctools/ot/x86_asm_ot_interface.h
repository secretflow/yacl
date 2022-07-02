#pragma once

#include "yasl/mpctools/ot/base_ot_interface.h"

namespace yasl {

class X86AsmOtInterface : public BaseOTInterface {
 public:
  // Receiver interface
  void Send(const std::shared_ptr<link::Context>& ctx,
            absl::Span<std::array<Block, 2>> send_blocks) override;

  void Recv(const std::shared_ptr<link::Context>& ctx,
            const std::vector<bool>& choices,
            absl::Span<Block> recv_blocks) override;
};

}  // namespace yasl
