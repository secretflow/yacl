#include "yasl/mpctools/ot/base_ot.h"

#if defined (__linux__) && defined (__x86_64)
#include "cpu_features/cpuinfo_x86.h"

#include "yasl/mpctools/ot/x86_asm_ot_interface.h"
#endif

#include "yasl/base/exception.h"
#include "yasl/mpctools/ot/portable_ot_interface.h"

namespace yasl {
namespace {

std::unique_ptr<BaseOTInterface> GetOtInterface() {
#if defined (__linux__) && defined (__x86_64)
  // x86 asm ot does not support macOS
  static const auto features = cpu_features::GetX86Info().features;
  if (features.avx) {
    return std::make_unique<X86AsmOtInterface>();
  }
#endif
  return std::make_unique<PortableOtInterface>();
}

}  // namespace

// Abstract class anchor
BaseOTInterface::~BaseOTInterface() = default;

void BaseOtRecv(const std::shared_ptr<link::Context>& ctx,
                const std::vector<bool>& choices,
                absl::Span<Block> recv_blocks) {
  YASL_ENFORCE_EQ(ctx->WorldSize(), 2u);
  YASL_ENFORCE_EQ(choices.size(), recv_blocks.size());
  YASL_ENFORCE(!choices.empty(), "empty choices");

  auto ot_interface = GetOtInterface();
  ot_interface->Recv(ctx, choices, recv_blocks);
}

void BaseOtSend(const std::shared_ptr<link::Context>& ctx,
                absl::Span<std::array<Block, 2>> send_blocks) {
  YASL_ENFORCE(!send_blocks.empty(), "empty inputs");

  auto ot_interface = GetOtInterface();
  ot_interface->Send(ctx, send_blocks);
}

}  // namespace yasl
