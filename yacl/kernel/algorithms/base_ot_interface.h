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

#include "yacl/base/dynamic_bitset.h"
#include "yacl/base/int128.h"
#include "yacl/link/link.h"

namespace yacl::crypto {

using Block = uint128_t;

class BaseOTInterface {
 public:
  virtual ~BaseOTInterface();
  virtual void Send(const std::shared_ptr<link::Context>& ctx,
                    absl::Span<std::array<Block, 2>> send_blocks) = 0;
  virtual void Recv(const std::shared_ptr<link::Context>& ctx,
                    const dynamic_bitset<uint128_t>& choices,
                    absl::Span<Block> recv_blocks) = 0;
};

}  // namespace yacl::crypto
