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

#include <array>
#include <vector>

#include "yacl/base/int128.h"

namespace yacl {

struct BaseRecvOptions {
  // TODO(shuyan.ycf): Wrap a bit choice class.
  // Receiver choices.
  std::vector<bool> choices;
  // Received blocks.
  // Choose uint128_t as block so that it can be perfectly used as AES-PRG seed.
  std::vector<uint128_t> blocks;
};

struct BaseSendOptions {
  // Sender received blocks.
  // Choose uint128_t as block so that it can be perfectly used as AES-PRG seed.
  std::vector<std::array<uint128_t, 2>> blocks;
};

}  // namespace yacl