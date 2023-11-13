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
#include <cstddef>
#include <functional>
#include <string_view>
#include <utility>

#include "yacl/base/exception.h"

namespace yacl {

// A buffer is a RAII object that represents an in memory buffer.
class Buffer final {
  std::byte* ptr_{nullptr};
  int64_t size_{0};
  int64_t capacity_{0};
  std::function<void(void*)> deleter_;

 public:
  // Type traits
  using value_type = std::byte;

  // default constructor, create an empty buffer.
  Buffer() = default;
  explicit Buffer(int64_t size) : size_(size), capacity_(size) {
    YACL_ENFORCE(size >= 0);
    // C++17 ensures alignment of allocated memory is >=
    // __STDCPP_DEFAULT_NEW_ALIGNMENT__ Which should be 16
    ptr_ = new std::byte[size];
  }

  Buffer(int64_t size, int64_t cap) : size_(size), capacity_(cap) {
    YACL_ENFORCE(size >= 0 && cap >= size,
                 "Illegal size & cap, size={}, cap={}", size, cap);
    // C++17 ensures alignment of allocated memory is >=
    // __STDCPP_DEFAULT_NEW_ALIGNMENT__ Which should be 16
    ptr_ = new std::byte[cap];
  }

  template <typename ByteContainer,
            std::enable_if_t<sizeof(typename ByteContainer::value_type) == 1,
                             bool> = true>
  explicit Buffer(const ByteContainer& u) : Buffer(u.data(), u.size()) {}

  // Allocate a new buffer and copy the contents of ptr
  Buffer(const void* ptr, size_t size) {
    resize(static_cast<int64_t>(size));
    if (size > 0) {
      std::memcpy(ptr_, ptr, size);
    }
  }

  // Construct a Buffer object from a block of already allocated memory
  // Buffer will take the ownership of ptr
  Buffer(void* ptr, size_t size, const std::function<void(void*)>& deleter) {
    YACL_ENFORCE(reinterpret_cast<uintptr_t>(ptr) % 16 == 0,
                 "The input buffer is not aligned");

    size_ = size;
    capacity_ = size;
    ptr_ = static_cast<std::byte*>(ptr);
    deleter_ = deleter;
  }

  ~Buffer() { reset(); }

  Buffer(const Buffer& other) { *this = other; }
  Buffer& operator=(const Buffer& other) {
    if (&other != this) {
      resize(other.size_);
      std::copy(other.ptr_, other.ptr_ + other.size_, ptr_);
    }
    return *this;
  }

  Buffer(Buffer&& other) noexcept { *this = std::move(other); };
  Buffer& operator=(Buffer&& other) noexcept {
    if (this != &other) {
      std::swap(ptr_, other.ptr_);
      std::swap(size_, other.size_);
      std::swap(capacity_, other.capacity_);
      std::swap(deleter_, other.deleter_);
    }
    return *this;
  }

  template <typename T = void>
  T* data() {
    return reinterpret_cast<T*>(ptr_);
  }
  template <typename T = void>
  T const* data() const {
    return reinterpret_cast<T const*>(ptr_);
  }

  // return size of the buffer, in bytes.
  int64_t size() const { return size_; }
  int64_t capacity() const { return capacity_; }

  bool operator==(const Buffer& other) const {
    if (size_ != other.size_) {
      return false;
    }

    return (std::memcmp(ptr_, other.ptr_, size_) == 0);
  }

  operator std::string_view() const {
    return size_ == 0 ? std::string_view()
                      : std::string_view(reinterpret_cast<char*>(ptr_), size_);
  }

  void resize(int64_t new_size) {
    if (new_size <= capacity_) {
      size_ = new_size;
      return;
    }

    std::byte* new_ptr = nullptr;
    if (new_size > 0) {
      new_ptr = new std::byte[new_size];
      if (ptr_ != nullptr) {
        std::copy(ptr_, ptr_ + std::min(new_size, size_), new_ptr);
      }
    }

    reset();

    ptr_ = new_ptr;
    size_ = new_size;
    capacity_ = new_size;
    YACL_ENFORCE(size_ == 0 || ptr_ != nullptr, "new size = {}", new_size);
  }

  void reserve(int64_t new_cap) {
    YACL_ENFORCE(new_cap >= size_,
                 "reserve() cannot be used to reduce the size of Buffer,to "
                 "that end resize() is provided. size()={}, new_cap={}",
                 size_, new_cap);

    if (new_cap <= capacity_) {
      return;
    }

    auto* new_ptr = new std::byte[new_cap];
    if (ptr_ != nullptr && size_ > 0) {
      std::copy(ptr_, ptr_ + size_, new_ptr);
    }

    auto sz = size_;
    reset();

    ptr_ = new_ptr;
    size_ = sz;
    capacity_ = new_cap;
  }

  void* release() {
    void* tmp = ptr_;
    ptr_ = nullptr;
    size_ = 0;
    capacity_ = 0;
    return tmp;
  }

  void reset() {
    if (deleter_ != nullptr) {
      deleter_(reinterpret_cast<void*>(ptr_));
    } else {
      delete[] ptr_;
    }
    deleter_ = nullptr;
    ptr_ = nullptr;
    size_ = 0;
    capacity_ = 0;
  }
};

std::ostream& operator<<(std::ostream& out, const Buffer& v);

}  // namespace yacl
