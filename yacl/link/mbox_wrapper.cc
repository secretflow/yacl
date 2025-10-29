// Copyright 2025 Ant Group Co., Ltd.
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

#include "yacl/link/mbox_wrapper.h"

#include <cstring>

namespace yacl::link {

MboxWrapper::MboxWrapper(mbox_t* mbox, size_t rank, size_t world_size,
                         bool take_ownership)
    : mbox_(mbox),
      owns_mbox_(take_ownership),
      rank_(rank),
      world_size_(world_size) {
  if (mbox_ == nullptr) {
    throw std::invalid_argument("Cannot wrap nullptr mbox");
  }
}

MboxWrapper::~MboxWrapper() {
  if (mbox_ != nullptr && owns_mbox_) {
    mbox_destroy(mbox_);
    mbox_ = nullptr;
  }
}

MboxWrapper::MboxWrapper(MboxWrapper&& other) noexcept
    : mbox_(other.mbox_),
      owns_mbox_(other.owns_mbox_),
      rank_(other.rank_),
      world_size_(other.world_size_) {
  other.mbox_ = nullptr;
  other.owns_mbox_ = false;
}

MboxWrapper& MboxWrapper::operator=(MboxWrapper&& other) noexcept {
  if (this != &other) {
    if (mbox_ != nullptr && owns_mbox_) {
      mbox_destroy(mbox_);
    }

    mbox_ = other.mbox_;
    owns_mbox_ = other.owns_mbox_;
    rank_ = other.rank_;
    world_size_ = other.world_size_;

    other.mbox_ = nullptr;
    other.owns_mbox_ = false;
    other.rank_ = 0;
    other.world_size_ = 1;
  }
  return *this;
}

void MboxWrapper::Send(size_t dst, std::string_view key,
                       absl::Span<const uint8_t> data) {
  mbox_error_t result =
      mbox_send(mbox_, dst, key.data(), data.data(), data.size());

  switch (result) {
    case MBOX_SUCCESS:
      return;
    case MBOX_ERROR_INVALID_ARGUMENT:
      throw std::invalid_argument("Invalid arguments provided to Send");
    case MBOX_ERROR_MEMORY:
      throw std::bad_alloc();
    case MBOX_ERROR_NETWORK:
      throw std::runtime_error("Network error during Send");
    case MBOX_ERROR_INTERNAL:
      throw std::runtime_error("Internal error during Send");
    default:
      throw std::runtime_error("Unknown error during Send");
  }
}

std::vector<uint8_t> MboxWrapper::Recv(size_t src, std::string_view key,
                                       int64_t timeout_ms) {
  uint8_t* buffer = nullptr;
  size_t buffer_len = 0;

  mbox_error_t result =
      mbox_recv(mbox_, src, key.data(), timeout_ms, &buffer, &buffer_len);

  // Always create a cleanup guard for the buffer
  struct BufferGuard {
    uint8_t* ptr;
    ~BufferGuard() {
      if (ptr) free(ptr);
    }
  } guard{buffer};

  switch (result) {
    case MBOX_SUCCESS: {
      if (buffer == nullptr || buffer_len == 0) {
        return {};
      }
      std::vector<uint8_t> data(buffer, buffer + buffer_len);
      return data;
    }
    case MBOX_ERROR_INVALID_ARGUMENT:
      throw std::invalid_argument("Invalid arguments provided to Recv");
    case MBOX_ERROR_NOT_FOUND:
      return {};  // Return empty vector for timeout/not found
    case MBOX_ERROR_MEMORY:
      throw std::bad_alloc();
    case MBOX_ERROR_NETWORK:
      throw std::runtime_error("Network error during Recv");
    case MBOX_ERROR_INTERNAL:
      throw std::runtime_error("Internal error during Recv");
    default:
      throw std::runtime_error("Unknown error during Recv");
  }
}

}  // namespace yacl::link