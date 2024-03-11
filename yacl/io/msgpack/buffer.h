// Copyright 2023 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include "yacl/base/buffer.h"

namespace yacl::io {

class StreamBuffer {
 public:
  explicit StreamBuffer(Buffer *buf) : buf_(buf) {
    YACL_ENFORCE(buf != nullptr, "buf is nullptr");
    buf_->resize(0);
  }

  void write(const char *str, size_t len) {
    auto old_sz = buf_->size();
    buf_->resize(buf_->size() + len);
    std::memcpy(buf_->data<char>() + old_sz, str, len);
  }

  void write(std::string_view str) { write(str.data(), str.length()); }

  // reserve how much *extra* space
  void Expand(size_t extra_space) {
    buf_->reserve(static_cast<int64_t>(buf_->size() + extra_space));
  }

  char *PosLoc() const { return buf_->data<char>() + buf_->size(); }
  void IncPos(int64_t delta) { buf_->resize(buf_->size() + delta); }

  size_t WrittenSize() { return buf_->size(); }
  size_t FreeSize() const { return buf_->capacity() - buf_->size(); }

 private:
  Buffer *buf_;
};

class FixedBuffer {
 public:
  FixedBuffer(char *buf, size_t buf_len) : buf_(buf), buf_len_(buf_len) {}

  void write(const char *str, size_t len) {
    YACL_ENFORCE(
        pos_ + len <= buf_len_,
        "Dangerous!! buffer overflow, buf_len={}, pos={}, write_size={}",
        buf_len_, pos_, len);

    std::copy(str, str + len, buf_ + pos_);
    pos_ += len;
  }

  char *PosLoc() const { return buf_ + pos_; }

  void IncPos(int64_t delta) {
    int64_t new_pos = static_cast<int64_t>(pos_) + delta;
    YACL_ENFORCE(new_pos >= 0 && new_pos <= (int64_t)buf_len_,
                 "cannot update pos, delta={}, cur_pos={}, buf_len={}", delta,
                 pos_, buf_len_);
    pos_ = new_pos;
  }

  size_t WrittenSize() const { return pos_; }
  size_t FreeSize() const { return buf_len_ - pos_; }

 private:
  char *buf_;
  size_t buf_len_;
  size_t pos_ = 0;
};

// ShadowBuffer does not store any data.
// It is used solely for calculating the size of objects after msgpack
// serialization.
class ShadowBuffer {
 public:
  void write(const char *, size_t len) { size_ += len; }

  size_t GetDataSize() const { return size_; }

 private:
  size_t size_ = 0;
};

}  // namespace yacl::io
