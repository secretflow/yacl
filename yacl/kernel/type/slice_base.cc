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

#include "yacl/kernel/type/slice_base.h"

#include "yacl/base/exception.h"

namespace yacl::crypto {
//----------------------------------
//           Slice Base
//----------------------------------

void SliceBase::ConsistencyCheck() const {
  YACL_ENFORCE(
      internal_use_size_ > 0,
      "Internal slice size should be greater than 0, but got slice size: {}",
      internal_use_size_);
  YACL_ENFORCE(
      internal_buf_size_ > 0,
      "Internal buffer size should be greater than 0, but got buffer size: {}",
      internal_buf_size_);
  YACL_ENFORCE(internal_buf_size_ >= internal_use_size_,
               "Buffer size should great or equal to slice size, got {} >= {}",
               internal_buf_size_, internal_use_size_);
  YACL_ENFORCE(internal_buf_size_ >= internal_buf_ctr_, "Slice out of range!");
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

void SliceBase::Reset() {
  internal_use_ctr_ = 0;
  internal_use_size_ = 0;
  internal_buf_ctr_ = 0;
  internal_buf_size_ = 0;
  ConsistencyCheck();
}
}  // namespace yacl::crypto
