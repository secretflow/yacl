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

#pragma once

#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "absl/types/span.h"

#include "yacl/link/mbox_capi.h"

namespace yacl::link {

/// MboxWrapper provides a C++ wrapper around the C API mbox interface.
/// This replaces the previous abstract Mbox class with a concrete
/// implementation that uses the C API internally.
class MboxWrapper {
 public:
  /// Constructor - wraps an existing mbox_t instance.
  ///
  /// @param mbox The mbox instance to wrap.
  /// @param take_ownership If true, the wrapper will take ownership and destroy
  ///                       the mbox when destroyed. If false, the wrapper will
  ///                       not destroy the mbox.
  MboxWrapper(mbox_t* mbox, size_t rank, size_t world_size,
              bool take_ownership = false);

  /// Destructor - cleans up the mbox instance if owned.
  ~MboxWrapper();

  /// Move constructor.
  MboxWrapper(MboxWrapper&& other) noexcept;

  /// Move assignment operator.
  MboxWrapper& operator=(MboxWrapper&& other) noexcept;

  // Disable copy constructor and copy assignment
  MboxWrapper(const MboxWrapper&) = delete;
  MboxWrapper& operator=(const MboxWrapper&) = delete;

  /// Send a message to the specified destination.
  ///
  /// @param dst The destination rank.
  /// @param key The message key.
  /// @param data The message data.
  void Send(size_t dst, std::string_view key, absl::Span<const uint8_t> data);

  /// Receive a message from the specified source.
  ///
  /// @param src The source rank.
  /// @param key The message key.
  /// @param timeout_ms Timeout in milliseconds (-1 for infinite wait).
  /// @return The received message data, or empty vector if timeout/error.
  std::vector<uint8_t> Recv(size_t src, std::string_view key,
                            int64_t timeout_ms);

  /// Get the rank of this mbox instance.
  /// @return The rank (0-based index).
  size_t Rank() const { return rank_; }

  /// Get the world size (total number of parties).
  /// @return The world size.
  size_t WorldSize() const { return world_size_; }

 private:
  mbox_t* mbox_ = nullptr;
  bool owns_mbox_ = false;
  size_t rank_;
  size_t world_size_;
};

}  // namespace yacl::link