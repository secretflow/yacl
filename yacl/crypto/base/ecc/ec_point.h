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

#include <utility>
#include <variant>

#include "yacl/crypto/base/mpint/mp_int.h"

namespace yacl::crypto {

// Elliptic curve point Octet-String format
// See SECG standard for details: SEC 1, section 2.3. https://www.secg.org/
enum class PointOctetFormat {
  // The format is determined by the library itself.
  Autonomous,

  // ANSI X9.62 compressed format
  // The point is encoded as z||x, where the octet z specifies which solution of
  // the quadratic equation y is.
  // if y is even, output 0x02||x
  // if y is odd, output 0x03||x
  // if point is inf, output 0x00
  X962Compressed,

  // ANSI X9.62 uncompressed format
  // The point is encoded as z||x||y, where z is the octet 0x04
  X962Uncompressed,

  // ANSI X9.62 hybrid format
  // The point is encoded as z||x||y, where the octet z specifies which solution
  // of the quadratic equation y is. It's basically the uncompressed encoding
  // but the first byte encodes the evenness of y just like in compressed
  // format. It's designated by 0x06 and 0x07 in the first byte, and they have
  // the same meaning as 0x02 and 0x03 in compressed.
  X962Hybrid,
};

// Points represented in human-readable format
struct AffinePoint {
  MPInt x;
  MPInt y;
  MSGPACK_DEFINE(x, y);

  AffinePoint(MPInt x, MPInt y) : x(std::move(x)), y(std::move(y)) {}
  AffinePoint() = default;

  bool operator==(const AffinePoint &rhs) const;
  bool operator!=(const AffinePoint &rhs) const;

  std::string ToString() const;

  [[nodiscard]] Buffer Serialize() const;
  void Deserialize(ByteContainerView in);

  friend std::ostream &operator<<(std::ostream &os, const AffinePoint &point);
};

class AnyPointPtr {
 public:
  AnyPointPtr(void *point, std::function<void(void *)> deleter)
      : ptr_(point, std::move(deleter)) {}

  template <typename T>
  inline const T *get() const & {
    return reinterpret_cast<const T *>(ptr_.get());
  }

  template <typename T>
  inline T *get() & {
    return reinterpret_cast<T *>(ptr_.get());
  }

 private:
  std::shared_ptr<void> ptr_;
};

// Feel free to add more storage types if you need.
// Here is some example:
using Array32 = std::array<char, 32>;  // 256bits, enough to store X25519 point
using Array33 = std::array<char, 33>;  // 264bits, x coordinate + 1 sign bit
using Array64 = std::array<char, 64>;  // 512bits, store (x, y)

// The storage format inside EcPoint is explained by each curve itself, here is
// a black box
using EcPoint =
    std::variant<Array32, Array33, Array64, AnyPointPtr, AffinePoint>;

}  // namespace yacl::crypto
