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

#include <algorithm>
#include <random>
#include <utility>
#include <vector>

#include "yacl/crypto/primitives/ot/common.h"
#include "yacl/crypto/tools/prg.h"
#include "yacl/crypto/utils/rand.h"

namespace yacl::crypto {

inline BaseOtStore MakeBaseOt(size_t num) {
  BaseOtStore ot_store;
  ot_store.recv.choices = crypto::RandBits(num);
  std::random_device rd;
  Prg<uint128_t> gen(rd());
  for (size_t i = 0; i < num; ++i) {
    ot_store.send.blocks.push_back({gen(), gen()});
    ot_store.recv.blocks.push_back(
        ot_store.send.blocks[i][ot_store.recv.choices[i]]);
  }
  return ot_store;
}

inline uint32_t CreateRandomRangeNum(size_t n) {
  std::random_device rd;
  Prg<uint32_t> gen(rd());
  return gen() % n;
}

}  // namespace yacl::crypto