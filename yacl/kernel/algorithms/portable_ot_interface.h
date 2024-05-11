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

#ifndef HAS_OT_INTERFACE
#define HAS_OT_INTERFACE
#else
#error "OT interface already defined"
#endif

#include "yacl/kernel/algorithms/base_ot_interface.h"
#include "yacl/secparam.h"

/* security parameter declaration */
YACL_MODULE_DECLARE("base_ot_portable", SecParam::C::k128, SecParam::S::INF);

namespace yacl::crypto {

class PortableOtInterface : public BaseOTInterface {
 public:
  ~PortableOtInterface() override = default;

  void Send(const std::shared_ptr<link::Context>& ctx,
            absl::Span<std::array<Block, 2>> send_blocks) override;

  void Recv(const std::shared_ptr<link::Context>& ctx,
            const dynamic_bitset<uint128_t>& choices,
            absl::Span<Block> recv_blocks) override;
};

}  // namespace yacl::crypto
