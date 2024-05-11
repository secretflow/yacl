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

#include "yacl/kernel/algorithms/base_ot.h"

#include "yacl/base/exception.h"

namespace yacl::crypto {
namespace {

std::unique_ptr<BaseOTInterface> GetOtInterface() {
#if defined(__linux__) && defined(__x86_64)
  // x86 asm ot does not support macOS
  return std::make_unique<X86AsmOtInterface>();
#else
  return std::make_unique<PortableOtInterface>();
#endif
}

}  // namespace

// Abstract class anchor
BaseOTInterface::~BaseOTInterface() = default;

void BaseOtRecv(const std::shared_ptr<link::Context>& ctx,
                const dynamic_bitset<>& choices,
                absl::Span<Block> recv_blocks) {
  YACL_ENFORCE_EQ(ctx->WorldSize(), 2u);
  YACL_ENFORCE_EQ(choices.size(), recv_blocks.size());
  YACL_ENFORCE(!choices.empty(), "empty choices");

  auto ot_interface = GetOtInterface();
  ot_interface->Recv(ctx, choices, recv_blocks);
}

void BaseOtSend(const std::shared_ptr<link::Context>& ctx,
                absl::Span<std::array<Block, 2>> send_blocks) {
  YACL_ENFORCE(!send_blocks.empty(), "empty inputs");

  auto ot_interface = GetOtInterface();
  ot_interface->Send(ctx, send_blocks);
}

}  // namespace yacl::crypto
