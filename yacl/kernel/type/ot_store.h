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

#include "yacl/base/aligned_vector.h"
#include "yacl/base/dynamic_bitset.h"
#include "yacl/base/exception.h"
#include "yacl/base/int128.h"
#include "yacl/kernel/type/slice_base.h"
#include "yacl/link/context.h"

namespace yacl::crypto {

enum class OtStoreType { Normal, Compact };

// OT Receiver (for 1-out-of-2 OT)
//
// Data structure that stores multiple ot receiver's data (a.k.a. the choice and
// the chosen 1-out-of-2 message)
class OtRecvStore : public SliceBase {
 public:
  using BitBufPtr = std::shared_ptr<dynamic_bitset<uint128_t>>;
  using BlkBufPtr = std::shared_ptr<UninitAlignedVector<uint128_t>>;

  // full constructor for ot receiver store
  OtRecvStore(BitBufPtr bit_ptr, BlkBufPtr blk_ptr, uint64_t use_ctr,
              uint64_t use_size, uint64_t buf_ctr, uint64_t buf_size,
              OtStoreType type = OtStoreType::Normal);

  // empty constructor
  explicit OtRecvStore(uint64_t num, OtStoreType type = OtStoreType::Normal);

  // slice the ot store (changes the counters in original ot store)
  OtRecvStore NextSlice(uint64_t num);

  // slice the ot store (does not affect the original ot store)
  OtRecvStore Slice(uint64_t begin, uint64_t end) const;

  // get ot store type
  OtStoreType Type() const { return type_; }

  // reset ot store
  void Reset();

  // get the available ot number for this slice
  uint64_t Size() const { return GetUseSize(); }

  // -----------------
  // Manipulate blocks
  // -----------------

  // access a block element with the given index
  uint128_t GetBlock(uint64_t idx) const;

  // modify a block with a given slice index
  void SetBlock(uint64_t idx, uint128_t val);

  // get a span of the block
  absl::Span<uint128_t> GetBlkBufSpan();

  // get a buffer copy of block buf (in bytes)
  Buffer GetBlkBuf();

  // allow steal (in bytes)
  BlkBufPtr StealBlkBuf();

  // copy out the blocks (in bytes)
  UninitAlignedVector<uint128_t> CopyBlkBuf() const;

  // ------------------
  // Manipulate choices
  // ------------------

  // access a choice bit with a given slice index
  uint8_t GetChoice(uint64_t idx) const;
  // modify a choice bit(val) with a given slice index

  void SetChoice(uint64_t idx, bool val);
  // modify a choice bit(val) with a given slice index

  // flip a choice bit with a given slice index
  void FlipChoice(uint64_t idx);

  // get a buffer copy of bit buf (choice buf)
  Buffer GetBitBuf();

  // set bit buf
  void SetBitBuf(const dynamic_bitset<uint128_t>& in);

  // copy out the sliced choice buffer [wanring: low efficiency]
  dynamic_bitset<uint128_t> CopyBitBuf() const;

 private:
  // check the consistency of ot receiver store
  void ConsistencyCheck() const override;

  // [warning] please don't use compact mode unless you know what you are doing
  // In compact mode, we store one ot block and one choice bit in uint128_t,
  // thus the valid ot length is only 127 bits, which may incur security issues.
  OtStoreType type_ = OtStoreType::Normal;

  // Compact mode for COT (Receiver):
  //
  // Blocks Buffer: |-----block[0]----*|---.......--|-----block[n]----*|
  //                                  |                               |
  //                              choice[0]                        choice[n]

  BitBufPtr bit_buf_;  // store choices in normal mode, nullptr in compact mode
  BlkBufPtr blk_buf_;  // store blocks in normal mode; store blocks and choices
                       // in compact mode
};

// OT Sender (for 1-out-of-2 OT)
//
// Data structure that stores multiple ot sender's data (a.k.a. the ot messages)
class OtSendStore : public SliceBase {
 public:
  using BlkBufPtr = std::shared_ptr<UninitAlignedVector<uint128_t>>;

  // full constructor for ot receiver store
  OtSendStore(BlkBufPtr blk_ptr, uint128_t delta, uint64_t use_ctr,
              uint64_t use_size, uint64_t buf_ctr, uint64_t buf_size,
              OtStoreType type = OtStoreType::Normal);

  // empty constructor
  explicit OtSendStore(uint64_t num, OtStoreType type = OtStoreType::Normal);

  // slice the ot store (changes the counters in original ot store)
  OtSendStore NextSlice(uint64_t num);

  // slice the ot store (does not affect the original ot store)
  OtSendStore Slice(uint64_t begin, uint64_t end) const;

  // get ot store type
  OtStoreType Type() const { return type_; }

  // reset ot store
  void Reset();

  // get the available ot number for this slice
  uint64_t Size() const;

  // access the delta of the cot
  uint128_t GetDelta() const;

  // set the delta of the cot
  void SetDelta(uint128_t delta);

  // access a block with the given index
  uint128_t GetBlock(uint64_t ot_idx, uint64_t msg_idx) const;

  // modify a block with the given index
  void SetNormalBlock(uint64_t ot_idx, uint64_t msg_idx, uint128_t val);

  // set a cot block
  void SetCompactBlock(uint64_t ot_idx, uint128_t val);

  // get a buffer copy of block buf
  Buffer GetBlkBuf();

  // get a span of block buf
  absl::Span<uint128_t> GetBlkBufSpan();

  // allow steal
  BlkBufPtr StealBlkBuf();

  // copy out cot blocks
  UninitAlignedVector<uint128_t> CopyCotBlkBuf() const;

 private:
  // check the consistency of ot receiver store
  void ConsistencyCheck() const override;

  // by default, compact mode stores correlated ot
  // and normal mode stores random ot
  OtStoreType type_ = OtStoreType::Normal;

  uint128_t delta_ = 0;  // store cot's delta
  BlkBufPtr blk_buf_;    // store blocks
};

}  // namespace yacl::crypto
