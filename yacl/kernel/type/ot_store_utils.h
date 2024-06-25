
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

#include "yacl/kernel/type/ot_store.h"

namespace yacl::crypto {

// Easier way of generate a ot_store pointer from a given choice buffer and
// a block buffer
OtRecvStore MakeOtRecvStore(const dynamic_bitset<uint128_t>& choices,
                            const UninitAlignedVector<uint128_t>& blocks);

OtRecvStore MakeOtRecvStore(const dynamic_bitset<uint128_t>& choices,
                            const std::vector<uint128_t>& blocks);

// Easier way of generate a compact cot_store pointer from a given block buffer
// Note: Compact ot is correlated-ot (or called delta-ot)
OtRecvStore MakeCompactOtRecvStore(
    const UninitAlignedVector<uint128_t>& blocks);

OtRecvStore MakeCompactOtRecvStore(const std::vector<uint128_t>& blocks);

OtRecvStore MakeCompactOtRecvStore(UninitAlignedVector<uint128_t>&& blocks);

OtRecvStore MakeCompactOtRecvStore(std::vector<uint128_t>&& blocks);

// Easier way of generate a ot_store pointer from a given blocks buffer
OtSendStore MakeOtSendStore(
    const UninitAlignedVector<std::array<uint128_t, 2>>& blocks);

OtSendStore MakeOtSendStore(
    const std::vector<std::array<uint128_t, 2>>& blocks);

// Easier way of generate a compact cot_store pointer from a given blocks
// buffer and cot delta
// Note: Compact ot is correlated-ot (or called delta-ot)
OtSendStore MakeCompactOtSendStore(const std::vector<uint128_t>& blocks,
                                   uint128_t delta);

OtSendStore MakeCompactOtSendStore(const UninitAlignedVector<uint128_t>& blocks,
                                   uint128_t delta);

OtSendStore MakeCompactOtSendStore(std::vector<uint128_t>&& blocks,
                                   uint128_t delta);

OtSendStore MakeCompactOtSendStore(UninitAlignedVector<uint128_t>&& blocks,
                                   uint128_t delta);

// OT Store (for mocking only)
class MockOtStore {
 public:
  OtSendStore send;
  OtRecvStore recv;
};

// Locally mock ots
MockOtStore MockRots(uint64_t num);
MockOtStore MockRots(uint64_t num, dynamic_bitset<uint128_t> choices);
MockOtStore MockCots(uint64_t num, uint128_t delta);
MockOtStore MockCots(uint64_t num, uint128_t delta,
                     dynamic_bitset<uint128_t> choices);

// Note: Compact ot is correlated-ot (or called delta-ot)
MockOtStore MockCompactOts(uint64_t num);

}  // namespace yacl::crypto
