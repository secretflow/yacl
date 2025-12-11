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

#include "yacl/kernel/type/ot_store.h"

#include <cstring>
#include <memory>
#include <utility>

#include "yacl/base/exception.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/crypto/tools/prg.h"

namespace yacl::crypto {

//----------------------------------
//           OtRecvStore
//----------------------------------

OtRecvStore::OtRecvStore(BitBufPtr bit_ptr, BlkBufPtr blk_ptr, uint64_t use_ctr,
                         uint64_t use_size, uint64_t buf_ctr, uint64_t buf_size,
                         OtStoreType type)
    : type_(type), bit_buf_(std::move(bit_ptr)), blk_buf_(std::move(blk_ptr)) {
  InitCtrs(use_ctr, use_size, buf_ctr, buf_size);
  ConsistencyCheck();
}

OtRecvStore::OtRecvStore(uint64_t num, OtStoreType type) : type_(type) {
  // in normal mode, we need to init bit_buf_ to store choices
  if (type_ == OtStoreType::Normal) {
    bit_buf_ = std::make_shared<dynamic_bitset<uint128_t>>(num);
  }
  blk_buf_ = std::make_shared<UninitAlignedVector<uint128_t>>(num, 0);
  InitCtrs(0, num, 0, num);
  ConsistencyCheck();
}

OtRecvStore OtRecvStore::NextSlice(uint64_t num) {
  // Recall: A new slice looks like the following:
  //
  // |---------------|-----slice-----|----------------| internal buffer
  // a               b               c                d
  //
  // internal_use_ctr_ = b
  // internal_use_size_ = c - b
  // internal_buf_ctr_ = b
  // internal_buf_size_ = c

  auto out = Slice(GetBufCtr(), GetBufCtr() + num);
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

// FIX ME: a const OtRecvStore could execute "Slice" to get a non-const
// OtRecvStore, which could change Block Value by "SetBlock"
OtRecvStore OtRecvStore::Slice(uint64_t begin, uint64_t end) const {
  // Recall: A new slice looks like the following:
  //
  // |---------------|-----slice-----|----------------| internal buffer
  // a               b               c                d
  //
  // internal_use_ctr_ = b
  // internal_use_size_ = c - b
  // internal_buf_ctr_ = b
  // internal_buf_size_ = c

  uint64_t slice_use_ctr = begin;         // in blocks
  uint64_t slice_use_size = end - begin;  // in blocks
  uint64_t slice_buf_ctr = begin;         // in blocks
  uint64_t slice_buf_size = end;          // in blocks

  return {bit_buf_,      blk_buf_,       slice_use_ctr, slice_use_size,
          slice_buf_ctr, slice_buf_size, type_};
}

void OtRecvStore::Reset() {
  SliceBase::Reset();
  bit_buf_.reset();
  blk_buf_.reset();
  type_ = OtStoreType::Compact;
  ConsistencyCheck();
}

uint128_t OtRecvStore::GetBlock(uint64_t idx) const {
  YACL_ENFORCE(idx < GetUseSize());
  return blk_buf_->operator[](GetBufIdx(idx));
}

void OtRecvStore::SetBlock(uint64_t idx, uint128_t val) {
  blk_buf_->operator[](GetBufIdx(idx)) = val;
}

absl::Span<uint128_t> OtRecvStore::GetBlkBufSpan() {
  YACL_ENFORCE(!IsSliced());
  return {reinterpret_cast<uint128_t*>(blk_buf_->data()), GetBufSize()};
}

Buffer OtRecvStore::GetBlkBuf() {
  // Constructs Buffer object by copy
  return {blk_buf_->data(), blk_buf_->size() * sizeof(uint128_t)};
}

OtRecvStore::BlkBufPtr OtRecvStore::StealBlkBuf() {
  YACL_ENFORCE(blk_buf_.use_count() == 1);
  auto ret = std::move(blk_buf_);
  Reset();
  return ret;
}

UninitAlignedVector<uint128_t> OtRecvStore::CopyBlkBuf() const {
  return {blk_buf_->begin() + internal_use_ctr_,
          blk_buf_->begin() + internal_use_ctr_ + internal_use_size_};
}

uint8_t OtRecvStore::GetChoice(uint64_t idx) const {
  YACL_ENFORCE(idx < GetUseSize(),
               "required idx={} is larger than the allowed use size={}", idx,
               GetUseSize());
  if (type_ == OtStoreType::Compact) {
    return blk_buf_->operator[](GetBufIdx(idx)) & 0x1;
  } else {
    return bit_buf_->operator[](GetBufIdx(idx));
  }
}

void OtRecvStore::SetChoice(uint64_t idx, bool val) {
  YACL_ENFORCE(type_ == OtStoreType::Normal,
               "Manipulating choice is currently not allowed in compact mode");
  bit_buf_->operator[](GetBufIdx(idx)) = val;
}

void OtRecvStore::FlipChoice(uint64_t idx) {
  YACL_ENFORCE(type_ == OtStoreType::Normal,
               "Manipulating choice is currently not allowed in compact mode");
  bit_buf_->operator[](GetBufIdx(idx)).flip();
}

Buffer OtRecvStore::GetBitBuf() {
  // Constructs Buffer object by copy
  return {bit_buf_->data(), bit_buf_->num_blocks() * sizeof(uint128_t)};
}

void OtRecvStore::SetBitBuf(const dynamic_bitset<uint128_t>& in) {
  bit_buf_ = std::make_shared<dynamic_bitset<uint128_t>>(in);
}

dynamic_bitset<uint128_t> OtRecvStore::CopyBitBuf() const {
  // [Warning] low efficiency
  if (type_ == OtStoreType::Compact) {
    dynamic_bitset<uint128_t> out(Size());
    for (size_t i = 0; i < Size(); ++i) {
      out[i] = GetBlock(i) & 0x1;
    }
    return out;
  }
  // YACL_ENFORCE(type_ == OtStoreType::Normal,
  //              "Copying choice is currently not allowed in compact mode");
  dynamic_bitset<uint128_t> out = *bit_buf_;  // copy
  out >>= GetUseCtr();
  out.resize(GetUseSize());
  return out;
}

void OtRecvStore::ConsistencyCheck() const {
  SliceBase::ConsistencyCheck();
  YACL_ENFORCE(blk_buf_->size() >= internal_buf_size_,
               "Actual buffer size: {}, but recorded "
               "internal buffer size is: {}",
               blk_buf_->size(), internal_buf_size_);
  if (type_ == OtStoreType::Normal) {
    YACL_ENFORCE_EQ(bit_buf_->size(), blk_buf_->size());
  }
}

//----------------------------------
//           OtSendStore
//----------------------------------

OtSendStore::OtSendStore(BlkBufPtr blk_ptr, uint128_t delta, uint64_t use_ctr,
                         uint64_t use_size, uint64_t buf_ctr, uint64_t buf_size,
                         OtStoreType type)
    : type_(type), delta_(delta), blk_buf_(std::move(blk_ptr)) {
  InitCtrs(use_ctr, use_size, buf_ctr, buf_size);
  ConsistencyCheck();
}

OtSendStore::OtSendStore(uint64_t num, OtStoreType type) : type_(type) {
  uint64_t buf_size = num;
  if (type_ == OtStoreType::Normal) {
    buf_size = num * 2;
  }

  blk_buf_ = std::make_shared<UninitAlignedVector<uint128_t>>(buf_size, 0);
  InitCtrs(0, buf_size, 0, buf_size);
  ConsistencyCheck();
}

void OtSendStore::Reset() {
  SliceBase::Reset();
  blk_buf_.reset();
  type_ = OtStoreType::Compact;
  ConsistencyCheck();
}

void OtSendStore::ConsistencyCheck() const {
  SliceBase::ConsistencyCheck();
  YACL_ENFORCE(blk_buf_->size() >= internal_buf_size_,
               "Actual buffer size: {}, but recorded "
               "internal buffer size is: {}",
               blk_buf_->size(), internal_buf_size_);
}

// FIX ME: a const OtSendStore could execute "Slice" to get a non-const
// OtSendStore, which could change Block Value by "SetBlock"
OtSendStore OtSendStore::Slice(uint64_t begin, uint64_t end) const {
  const uint64_t ot_blk_num = (type_ == OtStoreType::Compact) ? 1 : 2;
  // Recall: A new slice looks like the following:
  //
  // |---------------|-----slice-----|----------------| internal buffer
  // a               b               c                d
  //
  // internal_use_ctr_ = b
  // internal_use_size_ = c - b
  // internal_buf_ctr_ = b
  // internal_buf_size_ = c

  uint64_t slice_use_ctr = begin * ot_blk_num;           // in blocks
  uint64_t slice_use_size = (end - begin) * ot_blk_num;  // in blocks
  uint64_t slice_buf_ctr = begin * ot_blk_num;           // in blocks
  uint64_t slice_buf_size = end * ot_blk_num;            // in blocks

  return {blk_buf_,      delta_,         slice_use_ctr, slice_use_size,
          slice_buf_ctr, slice_buf_size, type_};
}

OtSendStore OtSendStore::NextSlice(uint64_t num) {
  const uint64_t ot_blk_num = (type_ == OtStoreType::Compact) ? 1 : 2;
  // Recall: A new slice looks like the following:
  //
  // |---------------|-----slice-----|----------------| internal buffer
  // a               b               c                d
  //
  // internal_use_ctr_ = b
  // internal_use_size_ = c - b
  // internal_buf_ctr_ = b
  // internal_buf_size_ = c
  auto out = Slice(GetBufCtr() / ot_blk_num, GetBufCtr() / ot_blk_num + num);

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

uint64_t OtSendStore::Size() const {
  if (type_ == OtStoreType::Compact) {
    return GetUseSize();
  } else {
    return GetUseSize() / 2;
  }
}

uint128_t OtSendStore::GetDelta() const {
  YACL_ENFORCE(delta_ != 0,
               "Error: You either call GetDelta() for a random ot store, or "
               "accidentally set cot's delta to 0.");
  return delta_;
}

void OtSendStore::SetDelta(uint128_t delta) {
  YACL_ENFORCE(delta != 0, "Error, you can not set delta to zero.");
  delta_ = delta;
}

uint128_t OtSendStore::GetBlock(uint64_t ot_idx, uint64_t msg_idx) const {
  YACL_ENFORCE(msg_idx == 0 || msg_idx == 1);
  const uint64_t ot_blk_num = (type_ == OtStoreType::Compact) ? 1 : 2;
  if (delta_ == 0) {  // rot must be normal mode
    return blk_buf_->operator[](GetBufIdx(2 * ot_idx) + msg_idx);
  } else {  // cot could be normal mode or compact mode
    return blk_buf_->operator[](GetBufIdx(ot_blk_num * ot_idx)) ^
           (delta_ * msg_idx);
  }
}

void OtSendStore::SetNormalBlock(uint64_t ot_idx, uint64_t msg_idx,
                                 uint128_t val) {
  YACL_ENFORCE(type_ == OtStoreType::Normal,
               "Manipulating ot messages is not allowed in compact mode");
  YACL_ENFORCE(msg_idx == 0 || msg_idx == 1);
  blk_buf_->operator[](GetBufIdx(ot_idx * 2 + msg_idx)) = val;
}

void OtSendStore::SetCompactBlock(uint64_t ot_idx, uint128_t val) {
  YACL_ENFORCE(type_ == OtStoreType::Compact,
               "SetCompactBlock() is only allowed in compact mode");
  blk_buf_->operator[](GetBufIdx(ot_idx)) = val;
}

Buffer OtSendStore::GetBlkBuf() {
  // Constructs Buffer object by copy
  return {blk_buf_->data(), blk_buf_->size() * sizeof(uint128_t)};
}

absl::Span<uint128_t> OtSendStore::GetBlkBufSpan() {
  YACL_ENFORCE(!IsSliced());
  return {reinterpret_cast<uint128_t*>(blk_buf_->data()), GetBufSize()};
}

OtSendStore::BlkBufPtr OtSendStore::StealBlkBuf() {
  YACL_ENFORCE(blk_buf_.use_count() == 1);
  auto ret = std::move(blk_buf_);
  Reset();
  return ret;
}

UninitAlignedVector<uint128_t> OtSendStore::CopyCotBlkBuf() const {
  YACL_ENFORCE(type_ == OtStoreType::Compact,
               "CopyCotBlkBuf() is only allowed in compact mode");
  return {blk_buf_->begin() + internal_buf_ctr_,
          blk_buf_->begin() + internal_buf_ctr_ + internal_use_size_};
}

}  // namespace yacl::crypto
