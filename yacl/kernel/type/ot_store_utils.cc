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

#include "yacl/kernel/type/ot_store_utils.h"

#include "yacl/crypto/rand/rand.h"
#include "yacl/crypto/tools/prg.h"

namespace yacl::crypto {

MockOtStore MockRots(uint64_t num) {
  auto recv_choices = RandBits<dynamic_bitset<uint128_t>>(num);
  return MockRots(num, recv_choices);
}

MockOtStore MockRots(uint64_t num, dynamic_bitset<uint128_t> choices) {
  YACL_ENFORCE(choices.size() == num);
  UninitAlignedVector<uint128_t> recv_blocks;
  UninitAlignedVector<std::array<uint128_t, 2>> send_blocks;

  Prg<uint128_t> gen(FastRandSeed());
  for (uint64_t i = 0; i < num; ++i) {
    send_blocks.push_back({gen(), gen()});
    recv_blocks.push_back(send_blocks[i][choices[i]]);
  }

  return {MakeOtSendStore(send_blocks),            // sender is normal
          MakeOtRecvStore(choices, recv_blocks)};  // receiver is normal
}

MockOtStore MockCots(uint64_t num, uint128_t delta) {
  auto recv_choices = RandBits<dynamic_bitset<uint128_t>>(num);
  return MockCots(num, delta, recv_choices);
}

MockOtStore MockCots(uint64_t num, uint128_t delta,
                     dynamic_bitset<uint128_t> choices) {
  YACL_ENFORCE(choices.size() == num);
  UninitAlignedVector<uint128_t> recv_blocks;
  UninitAlignedVector<uint128_t> send_blocks;

  Prg<uint128_t> gen(FastRandSeed());
  for (uint64_t i = 0; i < num; ++i) {
    auto msg = gen();
    send_blocks.push_back(msg);
    if (!choices[i]) {
      recv_blocks.push_back(send_blocks[i]);
    } else {
      recv_blocks.push_back(send_blocks[i] ^ delta);
    }
  }

  return {MakeCompactOtSendStore(send_blocks, delta),  // sender is compact
          MakeOtRecvStore(choices, recv_blocks)};      // receiver is normal
}

MockOtStore MockCompactOts(uint64_t num) {
  uint128_t delta = FastRandU128();
  delta |= 0x1;  // make sure its last bits = 1;
  UninitAlignedVector<uint128_t> recv_blocks;
  UninitAlignedVector<uint128_t> send_blocks;

  Prg<uint128_t> gen(FastRandSeed());
  for (uint64_t i = 0; i < num; ++i) {
    auto recv_msg = gen();
    auto choice = recv_msg & 0x1;
    send_blocks.push_back(recv_msg ^ (choice * delta));
    recv_blocks.push_back(recv_msg);
  }

  return {MakeCompactOtSendStore(send_blocks, delta),  // sender is compact
          MakeCompactOtRecvStore(recv_blocks)};        // receiver is compact
}

OtSendStore MakeOtSendStore(
    const std::vector<std::array<uint128_t, 2>>& blocks) {
  // warning: copy
  auto buf_ptr =
      std::make_shared<UninitAlignedVector<uint128_t>>(blocks.size() * 2);
  memcpy(buf_ptr->data(), blocks.data(), buf_ptr->size() * sizeof(uint128_t));

  return {buf_ptr,
          0,
          0,
          blocks.size() * 2,
          0,
          blocks.size() * 2,
          OtStoreType::Normal};
}

OtSendStore MakeOtSendStore(
    const UninitAlignedVector<std::array<uint128_t, 2>>& blocks) {
  // warning: copy
  auto buf_ptr =
      std::make_shared<UninitAlignedVector<uint128_t>>(blocks.size() * 2);
  memcpy(buf_ptr->data(), blocks.data(), buf_ptr->size() * sizeof(uint128_t));

  return {buf_ptr,
          0,
          0,
          blocks.size() * 2,
          0,
          blocks.size() * 2,
          OtStoreType::Normal};
}

OtSendStore MakeCompactOtSendStore(const std::vector<uint128_t>& blocks,
                                   uint128_t delta) {
  // warning: copy
  auto buf_ptr =
      std::make_shared<UninitAlignedVector<uint128_t>>(blocks.size());
  std::memcpy(buf_ptr->data(), blocks.data(),
              blocks.size() * sizeof(uint128_t));  // copy

  return {buf_ptr,
          delta,
          0,
          buf_ptr->size(),
          0,
          buf_ptr->size(),
          OtStoreType::Compact};
}

OtSendStore MakeCompactOtSendStore(const UninitAlignedVector<uint128_t>& blocks,
                                   uint128_t delta) {
  // warning: copy
  auto buf_ptr = std::make_shared<UninitAlignedVector<uint128_t>>(blocks);

  return {buf_ptr,
          delta,
          0,
          buf_ptr->size(),
          0,
          buf_ptr->size(),
          OtStoreType::Compact};
}

OtSendStore MakeCompactOtSendStore(std::vector<uint128_t>&& blocks,
                                   uint128_t delta) {
  auto buf_ptr =
      std::make_shared<UninitAlignedVector<uint128_t>>(blocks.size());
  std::memcpy(buf_ptr->data(), blocks.data(),
              blocks.size() * sizeof(uint128_t));  // copy

  return {buf_ptr,
          delta,
          0,
          buf_ptr->size(),
          0,
          buf_ptr->size(),
          OtStoreType::Compact};
}

OtSendStore MakeCompactOtSendStore(UninitAlignedVector<uint128_t>&& blocks,
                                   uint128_t delta) {
  auto buf_ptr = std::make_shared<UninitAlignedVector<uint128_t>>(
      std::move(blocks));  // move

  return {buf_ptr,
          delta,
          0,
          buf_ptr->size(),
          0,
          buf_ptr->size(),
          OtStoreType::Compact};
}
OtRecvStore MakeOtRecvStore(const dynamic_bitset<uint128_t>& choices,
                            const std::vector<uint128_t>& blocks) {
  auto tmp1_ptr = std::make_shared<dynamic_bitset<uint128_t>>(choices);  // copy
  auto tmp2_ptr =
      std::make_shared<UninitAlignedVector<uint128_t>>(blocks.size());
  std::memcpy(tmp2_ptr->data(), blocks.data(),
              blocks.size() * sizeof(uint128_t));  // copy

  return {tmp1_ptr,         tmp2_ptr,           0, tmp1_ptr->size(), 0,
          tmp1_ptr->size(), OtStoreType::Normal};
}

OtRecvStore MakeOtRecvStore(const dynamic_bitset<uint128_t>& choices,
                            const UninitAlignedVector<uint128_t>& blocks) {
  auto tmp1_ptr = std::make_shared<dynamic_bitset<uint128_t>>(choices);  // copy
  auto tmp2_ptr =
      std::make_shared<UninitAlignedVector<uint128_t>>(blocks);  // copy

  return {tmp1_ptr,         tmp2_ptr,           0, tmp1_ptr->size(), 0,
          tmp1_ptr->size(), OtStoreType::Normal};
}

OtRecvStore MakeCompactOtRecvStore(const std::vector<uint128_t>& blocks) {
  auto tmp_ptr =
      std::make_shared<UninitAlignedVector<uint128_t>>(blocks.size());
  std::memcpy(tmp_ptr->data(), blocks.data(),
              blocks.size() * sizeof(uint128_t));  // copy

  return {nullptr,
          tmp_ptr,
          0,
          tmp_ptr->size(),
          0,
          tmp_ptr->size(),
          OtStoreType::Compact};
}

OtRecvStore MakeCompactOtRecvStore(
    const UninitAlignedVector<uint128_t>& blocks) {
  auto tmp_ptr =
      std::make_shared<UninitAlignedVector<uint128_t>>(blocks);  // copy

  return {nullptr,
          tmp_ptr,
          0,
          tmp_ptr->size(),
          0,
          tmp_ptr->size(),
          OtStoreType::Compact};
}

OtRecvStore MakeCompactOtRecvStore(std::vector<uint128_t>&& blocks) {
  auto tmp_ptr =
      std::make_shared<UninitAlignedVector<uint128_t>>(blocks.size());

  std::memcpy(tmp_ptr->data(), blocks.data(),
              blocks.size() * sizeof(uint128_t));  // copy

  return {nullptr,
          tmp_ptr,
          0,
          tmp_ptr->size(),
          0,
          tmp_ptr->size(),
          OtStoreType::Compact};
}

OtRecvStore MakeCompactOtRecvStore(UninitAlignedVector<uint128_t>&& blocks) {
  auto tmp_ptr = std::make_shared<UninitAlignedVector<uint128_t>>(
      std::move(blocks));  // move

  return {nullptr,
          tmp_ptr,
          0,
          tmp_ptr->size(),
          0,
          tmp_ptr->size(),
          OtStoreType::Compact};
}
}  // namespace yacl::crypto
