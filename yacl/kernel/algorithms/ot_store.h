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
#include "yacl/link/context.h"

namespace yacl::crypto {

enum class OtStoreType { Normal, Compact };

class SliceBase {
 public:
  // setters and getters
  bool IsSliced() const { return internal_buf_ctr_ != 0; }
  virtual ~SliceBase() = default;

  void ResetSlice() {
    internal_use_ctr_ = 0;
    internal_use_size_ = internal_buf_size_;
    internal_buf_ctr_ = 0;
  }

 protected:
  uint64_t GetUseCtr() const { return internal_use_ctr_; }
  uint64_t GetUseSize() const { return internal_use_size_; }
  uint64_t GetBufCtr() const { return internal_buf_ctr_; }
  uint64_t GetBufSize() const { return internal_buf_size_; }
  virtual void ConsistencyCheck() const;

  // init all interal values
  void InitCtrs(uint64_t use_ctr, uint64_t use_size, uint64_t buf_ctr,
                uint64_t buf_size);

  // get the internal buffer index from a slice index
  uint64_t GetBufIdx(uint64_t slice_idx) const;

  // manually increase the buffer counter by "size"
  void IncreaseBufCtr(uint64_t size);

  // reset all pointers
  void Reset();

  // An unused slice looks like the follwoing:
  //
  // |---------------|-----slice-----|----------------| internal buffer
  // a               b               c                d
  //
  // internal_use_ctr_ = b
  // internal_use_size_ = c - b
  // internal_buf_ctr_ = b
  // internal_buf_size_ = c
  //
  // where who slice this buffer looks like the following:
  //
  //
  // |---------------|-----slice-----|----------------| internal buffer
  // a               b               c                d
  //
  // internal_use_ctr_ = a
  // internal_use_size_ = d - a
  // internal_buf_ctr_ = c (since the underlying buffer is already sliced to c)
  // internal_buf_size_ = d - a

  uint64_t internal_use_ctr_ = 0;   // slice begin position in buffer
  uint64_t internal_use_size_ = 0;  // allowed slice size (read & wrtie)
  uint64_t internal_buf_ctr_ = 0;   // buffer use counter (next slice position)
  uint64_t internal_buf_size_ = 0;  // underlying buf max size
                                    // (will not be affected by slice op)
};

// OT Receiver (for 1-out-of-2 OT)
//
// Data structure that stores multiple ot receier's data (a.k.a. the choice and
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

  // get a buffer copy of choice buf
  Buffer GetChoiceBuf();

  // get a buffer copy of block buf
  Buffer GetBlockBuf();

  // reset ot store
  void Reset();

  // get the avaliable ot number for this slice1
  uint64_t Size() const { return GetUseSize(); }

  // access a choice bit with a given slice index
  uint8_t GetChoice(uint64_t idx) const;

  // access a block element with the given index
  uint128_t GetBlock(uint64_t idx) const;

  // modify a choice bit(val) with a given slice index
  void SetChoice(uint64_t idx, bool val);

  // modify a block with a given slice index
  void SetBlock(uint64_t idx, uint128_t val);

  // flip a choice bit with a given slice index
  void FlipChoice(uint64_t idx);

  // copy out the sliced choice buffer [wanring: low efficiency]
  dynamic_bitset<uint128_t> CopyChoice() const;

  // copy out the sliced choice buffer [wanring: low efficiency]
  UninitAlignedVector<uint128_t> CopyBlocks() const;

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

  // get a buffer copy of block buf
  Buffer GetBlockBuf();

  // reset ot store
  void Reset();

  // get the avaliable ot number for this slice
  uint64_t Size() const;

  // access the delta of the cot
  uint128_t GetDelta() const;

  // access a block with the given index
  uint128_t GetBlock(uint64_t ot_idx, uint64_t msg_idx) const;

  // set the delta of the cot
  void SetDelta(uint128_t delta);

  // modify a block with the given index
  void SetNormalBlock(uint64_t ot_idx, uint64_t msg_idx, uint128_t val);

  // set a cot block
  void SetCompactBlock(uint64_t ot_idx, uint128_t val);

  // copy out cot blocks
  UninitAlignedVector<uint128_t> CopyCotBlocks() const;

 private:
  // check the consistency of ot receiver store
  void ConsistencyCheck() const override;

  // by default, compact mode stores correlated ot
  // and normal mode stores random ot
  OtStoreType type_ = OtStoreType::Normal;

  uint128_t delta_ = 0;  // store cot's delta
  BlkBufPtr blk_buf_;    // store blocks
};

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
