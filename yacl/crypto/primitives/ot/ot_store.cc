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

#include "yacl/crypto/primitives/ot/ot_store.h"

#include <utility>

#include "yacl/base/exception.h"
#include "yacl/crypto/tools/prg.h"
#include "yacl/crypto/utils/rand.h"

namespace yacl::crypto {

//================================//
//           Slice Base           //
//================================//

void SliceBase::ConsistencyCheck() const {
  YACL_ENFORCE(internal_use_size_ > 0, "Invalid slice size, got {} > 0",
               internal_use_size_);
  YACL_ENFORCE(internal_buf_size_ > 0, "Invalid buffer size, got {} > 0",
               internal_buf_size_);
  YACL_ENFORCE(internal_buf_size_ >= internal_use_size_,
               "Buffer size should great or equal to slice size, got {} >= {}",
               internal_buf_size_, internal_use_size_);
  YACL_ENFORCE(internal_buf_size_ > internal_buf_ctr_, "Slice out of range!");
}

void SliceBase::InitCtrs(uint64_t use_ctr, uint64_t use_size, uint64_t buf_ctr,
                         uint64_t buf_size) {
  internal_use_ctr_ = use_ctr;
  internal_use_size_ = use_size;
  internal_buf_ctr_ = buf_ctr;
  internal_buf_size_ = buf_size;
  ConsistencyCheck();
}

uint64_t SliceBase::GetBufIdx(uint64_t slice_idx) const {
  YACL_ENFORCE(internal_use_size_ > slice_idx,
               "Slice index out of range, slice size: {}, but got index: {}",
               internal_use_size_, slice_idx);
  return internal_use_ctr_ + slice_idx;
}

void SliceBase::IncreaseBufCtr(uint64_t size) {
  YACL_ENFORCE(
      internal_buf_size_ - internal_buf_ctr_ >= size,
      "Increase buffer counter failed, not enough space, buffer left space: "
      "{}, but tried increase with size: {}",
      internal_buf_size_ - internal_buf_ctr_, size);
  internal_buf_ctr_ += size;
}

//================================//
//           OtRecvStore          //
//================================//

OtRecvStore::OtRecvStore(BitBufPtr bit_ptr, BlkBufPtr blk_ptr, uint64_t use_ctr,
                         uint64_t use_size, uint64_t buf_ctr, uint64_t buf_size,
                         bool compact_mode)
    : compact_mode_(compact_mode),
      bit_buf_(std::move(bit_ptr)),
      blk_buf_(std::move(blk_ptr)) {
  InitCtrs(use_ctr, use_size, buf_ctr, buf_size);
  ConsistencyCheck();
}

OtRecvStore::OtRecvStore(uint64_t num, bool compact_mode)
    : compact_mode_(compact_mode) {
  if (!compact_mode_) {  // in normal mode, we need to init bit_buf_ to store
                         // choices
    bit_buf_ = std::make_shared<dynamic_bitset<uint128_t>>(num);
  }
  blk_buf_ = std::make_shared<std::vector<uint128_t>>(num);
  InitCtrs(0, num, 0, num);
  ConsistencyCheck();
}

void OtRecvStore::ConsistencyCheck() const {
  SliceBase::ConsistencyCheck();
  YACL_ENFORCE(blk_buf_->size() >= internal_buf_size_,
               "Actual buffer size: {}, but recorded "
               "internal buffer size is: {}",
               blk_buf_->size(), internal_buf_size_);
  if (!compact_mode_) {
    YACL_ENFORCE_EQ(bit_buf_->size(), blk_buf_->size());
  }
}

std::shared_ptr<OtRecvStore> OtRecvStore::NextSlice(uint64_t num) {
  // Recall: A new slice looks like the follwoing:
  //
  // |---------------|-----slice-----|----------------| internal buffer
  // a               b               c                d
  //
  // internal_use_ctr_ = b
  // internal_use_size_ = c - b
  // internal_buf_ctr_ = b
  // internal_buf_size_ = c

  uint64_t slice_use_ctr = GetBufCtr();         // in blocks
  uint64_t slice_use_size = num;                // in blocks
  uint64_t slice_buf_ctr = GetBufCtr();         // in blocks
  uint64_t slice_buf_size = GetBufCtr() + num;  // in blocks

  auto out = std::make_shared<OtRecvStore>(bit_buf_, blk_buf_, slice_use_ctr,
                                           slice_use_size, slice_buf_ctr,
                                           slice_buf_size, compact_mode_);

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

  IncreaseBufCtr(num);  // increase the buffer counter

  return out;
}

uint8_t OtRecvStore::GetChoice(uint64_t idx) const {
  if (compact_mode_) {
    return blk_buf_->operator[](GetBufIdx(idx)) & 0x1;
  } else {
    return bit_buf_->operator[](GetBufIdx(idx));
  }
}

uint128_t OtRecvStore::GetBlock(uint64_t idx) const {
  return blk_buf_->operator[](GetBufIdx(idx));
}

void OtRecvStore::SetChoice(uint64_t idx, bool val) {
  YACL_ENFORCE(!compact_mode_,
               "Manipulating choice is currently not allowed in compact mode");
  bit_buf_->operator[](GetBufIdx(idx)) = val;
}

void OtRecvStore::SetBlock(uint64_t idx, uint128_t val) {
  blk_buf_->operator[](GetBufIdx(idx)) = val;
}

void OtRecvStore::FlipChoice(uint64_t idx) {
  YACL_ENFORCE(!compact_mode_,
               "Manipulating choice is currently not allowed in compact mode");
  bit_buf_->operator[](GetBufIdx(idx)).flip();
}

dynamic_bitset<uint128_t> OtRecvStore::CopyChoice() const {
  YACL_ENFORCE(!compact_mode_,
               "Copying choice is currently not allowed in compact mode");
  dynamic_bitset<uint128_t> out(bit_buf_->to_string());  // copy
  out >>= GetUseCtr();
  out.resize(GetUseSize());
  return out;
}

std::vector<uint128_t> OtRecvStore::CopyBlocks() const {
  return {blk_buf_->begin() + internal_use_ctr_,
          blk_buf_->begin() + internal_use_size_};
}

std::shared_ptr<OtRecvStore> MakeOtRecvStore(
    const dynamic_bitset<uint128_t>& choices,
    const std::vector<uint128_t>& blocks) {
  auto tmp1_ptr = std::make_shared<dynamic_bitset<uint128_t>>(choices);  // copy
  auto tmp2_ptr = std::make_shared<std::vector<uint128_t>>(blocks);      // copy

  uint64_t use_ctr = 0;
  uint64_t use_size = tmp1_ptr->size();
  uint64_t buf_ctr = 0;
  uint64_t buf_size = tmp1_ptr->size();

  return std::make_shared<OtRecvStore>(tmp1_ptr, tmp2_ptr, use_ctr, use_size,
                                       buf_ctr, buf_size, false);
}

std::shared_ptr<OtRecvStore> MakeCompactCotRecvStore(
    const std::vector<uint128_t>& blocks) {
  auto tmp_ptr = std::make_shared<std::vector<uint128_t>>(blocks);  // copy

  uint64_t use_ctr = 0;
  uint64_t use_size = tmp_ptr->size();
  uint64_t buf_ctr = 0;
  uint64_t buf_size = tmp_ptr->size();

  return std::make_shared<OtRecvStore>(nullptr, tmp_ptr, use_ctr, use_size,
                                       buf_ctr, buf_size, true);
}

//================================//
//           OtSendStore          //
//================================//

OtSendStore::OtSendStore(BlkBufPtr blk_ptr, uint128_t delta, uint64_t use_ctr,
                         uint64_t use_size, uint64_t buf_ctr, uint64_t buf_size,
                         bool compact_mode)
    : compact_mode_(compact_mode), delta_(delta), blk_buf_(std::move(blk_ptr)) {
  InitCtrs(use_ctr, use_size, buf_ctr, buf_size);
  ConsistencyCheck();
}

OtSendStore::OtSendStore(uint64_t num, bool compact_mode)
    : compact_mode_(compact_mode) {
  uint64_t buf_size = num;
  if (!compact_mode) {
    buf_size = num * 2;
  }

  blk_buf_ = std::make_shared<std::vector<uint128_t>>(buf_size);
  InitCtrs(0, buf_size, 0, buf_size);
  ConsistencyCheck();
}

void OtSendStore::ConsistencyCheck() const {
  SliceBase::ConsistencyCheck();
  YACL_ENFORCE(blk_buf_->size() >= internal_buf_size_,
               "Actual buffer size: {}, but recorded "
               "internal buffer size is: {}",
               blk_buf_->size(), internal_buf_size_);
}

std::shared_ptr<OtSendStore> OtSendStore::NextSlice(uint64_t num) {
  const uint64_t ot_blk_num = IsCompact() ? 1 : 2;

  // Recall: A new slice looks like the follwoing:
  //
  // |---------------|-----slice-----|----------------| internal buffer
  // a               b               c                d
  //
  // internal_use_ctr_ = b
  // internal_use_size_ = c - b
  // internal_buf_ctr_ = b
  // internal_buf_size_ = c

  uint64_t slice_use_ctr = GetBufCtr();                      // in blocks
  uint64_t slice_use_size = num * ot_blk_num;                // in blocks
  uint64_t slice_buf_ctr = GetBufCtr();                      // in blocks
  uint64_t slice_buf_size = GetBufCtr() + num * ot_blk_num;  // in blocks

  auto out = std::make_shared<OtSendStore>(blk_buf_, delta_, slice_use_ctr,
                                           slice_use_size, slice_buf_ctr,
                                           slice_buf_size);

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

  IncreaseBufCtr(num * ot_blk_num);

  return out;
}

void* OtSendStore::data() const { return static_cast<void*>(blk_buf_->data()); }

uint64_t OtSendStore::Size() const {
  if (compact_mode_) {
    return GetUseSize();
  } else {
    return GetUseSize() / 2;
  }
}

uint128_t OtSendStore::GetDelta() const {
  YACL_ENFORCE(delta_ != 0,
               "Error: You either call GetDelta() for a random ot store, or "
               "accidently set cot's delta to 0.");
  return delta_;
}

uint128_t OtSendStore::GetBlock(uint64_t ot_idx, uint64_t msg_idx) const {
  YACL_ENFORCE(msg_idx == 0 || msg_idx == 1);
  const uint64_t ot_blk_num = IsCompact() ? 1 : 2;
  if (delta_ == 0) {  // rot must be normal mode
    return blk_buf_->operator[](GetBufIdx(2 * ot_idx) + msg_idx);
  } else {  // cot could be normal mode or compact mode
    return blk_buf_->operator[](GetBufIdx(ot_blk_num * ot_idx)) ^
           (delta_ * msg_idx);
  }
}

void OtSendStore::SetDelta(uint128_t delta) {
  YACL_ENFORCE(delta != 0, "Error, you can not set delta to zero.");
  delta_ = delta;
}

void OtSendStore::SetNormalBlock(uint64_t ot_idx, uint64_t msg_idx,
                                 uint128_t val) {
  YACL_ENFORCE(!compact_mode_,
               "Manipulating ot messages is not allowed in compact mode");
  YACL_ENFORCE(msg_idx == 0 || msg_idx == 1);
  blk_buf_->operator[](GetBufIdx(ot_idx * 2 + msg_idx)) = val;
}

void OtSendStore::SetCompactBlock(uint64_t ot_idx, uint128_t val) {
  YACL_ENFORCE(compact_mode_,
               "SetCompactBlock() is only allowed in compact mode");
  blk_buf_->operator[](GetBufIdx(ot_idx)) = val;
}

std::vector<uint128_t> OtSendStore::CopyCotBlocks() const {
  YACL_ENFORCE(compact_mode_,
               "CopyCotBlocks() is only allowed in compact mode");
  return {blk_buf_->begin() + internal_buf_ctr_,
          blk_buf_->begin() + internal_use_size_};
}

std::shared_ptr<OtSendStore> MakeOtSendStore(
    const std::vector<std::array<uint128_t, 2>>& blocks) {
  // warning: copy
  auto buf_ptr = std::make_shared<std::vector<uint128_t>>(blocks.size() * 2);
  memcpy(buf_ptr->data(), blocks.data(), buf_ptr->size() * sizeof(uint128_t));

  uint64_t use_ctr = 0;
  uint64_t use_size = blocks.size() * 2;
  uint64_t buf_ctr = 0;
  uint64_t buf_size = blocks.size() * 2;

  return std::make_shared<OtSendStore>(buf_ptr, 0, use_ctr, use_size, buf_ctr,
                                       buf_size);
}

std::shared_ptr<OtSendStore> MakeCompactCotSendStore(
    const std::vector<uint128_t>& blocks, uint128_t delta) {
  // warning: copy
  auto buf_ptr = std::make_shared<std::vector<uint128_t>>(blocks);

  uint64_t use_ctr = 0;
  uint64_t use_size = blocks.size();
  uint64_t buf_ctr = 0;
  uint64_t buf_size = blocks.size();

  return std::make_shared<OtSendStore>(buf_ptr, delta, use_ctr, use_size,
                                       buf_ctr, buf_size, true);
}

MockOtStore MockRots(uint64_t num) {
  auto recv_choices = RandBits<dynamic_bitset<uint128_t>>(num);
  std::vector<uint128_t> recv_blocks;
  std::vector<std::array<uint128_t, 2>> send_blocks;

  Prg<uint128_t> gen(RandSeed());
  for (uint64_t i = 0; i < num; ++i) {
    send_blocks.push_back({gen(), gen()});
    recv_blocks.push_back(send_blocks[i][recv_choices[i]]);
  }

  return {MakeOtSendStore(send_blocks),                 // sender is normal
          MakeOtRecvStore(recv_choices, recv_blocks)};  // receiver is normal
}

MockOtStore MockCots(uint64_t num, uint128_t delta) {
  auto recv_choices = RandBits<dynamic_bitset<uint128_t>>(num);
  std::vector<uint128_t> recv_blocks;
  std::vector<uint128_t> send_blocks;

  Prg<uint128_t> gen(RandSeed());
  for (uint64_t i = 0; i < num; ++i) {
    auto msg = gen();
    send_blocks.push_back(msg);
    if (!recv_choices[i]) {
      recv_blocks.push_back(send_blocks[i]);
    } else {
      recv_blocks.push_back(send_blocks[i] ^ delta);
    }
  }

  return {MakeCompactCotSendStore(send_blocks, delta),  // sender is compact
          MakeOtRecvStore(recv_choices, recv_blocks)};  // receiver is normal
}

MockOtStore MockCompactCots(uint64_t num) {
  uint128_t delta = RandU128();
  delta |= 0x1;  // make sure its last bits = 1;
  std::vector<uint128_t> recv_blocks;
  std::vector<uint128_t> send_blocks;

  Prg<uint128_t> gen(RandSeed());
  for (uint64_t i = 0; i < num; ++i) {
    auto recv_msg = gen();
    auto choice = recv_msg & 0x1;
    send_blocks.push_back(recv_msg ^ (choice * delta));
    recv_blocks.push_back(recv_msg);
  }

  return {MakeCompactCotSendStore(send_blocks, delta),  // sender is compact
          MakeCompactCotRecvStore(recv_blocks)};        // receiver is compact
}

}  // namespace yacl::crypto
