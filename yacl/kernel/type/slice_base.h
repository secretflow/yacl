
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

#include <cstdint>

namespace yacl::crypto {

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
}  // namespace yacl::crypto
