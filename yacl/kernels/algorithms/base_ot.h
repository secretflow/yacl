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

#include <memory>
#include <vector>

#include "absl/types/span.h"

#include "yacl/base/dynamic_bitset.h"
#include "yacl/base/int128.h"
#include "yacl/kernels/algorithms/ot_store.h"
#include "yacl/link/link.h"
#include "yacl/secparam.h"

/* submodules */
#if defined(__linux__) && defined(__x86_64)
#include "yacl/kernels/algorithms/x86_asm_ot_interface.h"
#else
#include "yacl/kernels/algorithms/portable_ot_interface.h"
#endif

/* security parameter declaration */
// this module is only a wrapper, no need for security parameter definition

namespace yacl::crypto {

using Block = uint128_t;

void BaseOtRecv(const std::shared_ptr<link::Context>& ctx,
                const dynamic_bitset<uint128_t>& choices,
                absl::Span<Block> recv_blocks);

void BaseOtSend(const std::shared_ptr<link::Context>& ctx,
                absl::Span<std::array<Block, 2>> send_blocks);

// ==================== //
//   Support OT Store   //
// ==================== //

inline OtRecvStore BaseOtRecv(const std::shared_ptr<link::Context>& ctx,
                              const dynamic_bitset<uint128_t>& choices,
                              uint32_t num_ot) {
  std::vector<Block> blocks(num_ot);
  BaseOtRecv(ctx, choices, absl::MakeSpan(blocks));
  return MakeOtRecvStore(choices, blocks);  // FIXME: Drop explicit copy
}

inline OtSendStore BaseOtSend(const std::shared_ptr<link::Context>& ctx,
                              uint32_t num_ot) {
  std::vector<std::array<Block, 2>> blocks(num_ot);
  BaseOtSend(ctx, absl::MakeSpan(blocks));
  return MakeOtSendStore(blocks);  // FIXME: Drop explicit copy
}

}  // namespace yacl::crypto
