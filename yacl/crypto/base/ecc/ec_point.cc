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

#include "yacl/crypto/base/ecc/ec_point.h"

namespace yacl::crypto {

bool AffinePoint::operator==(const AffinePoint& rhs) const {
  return std::tie(x, y) == std::tie(rhs.x, rhs.y);
}

bool AffinePoint::operator!=(const AffinePoint& rhs) const {
  return !(rhs == *this);
}

std::string AffinePoint::ToString() const {
  return fmt::format("({}, {})", x, y);
}

Buffer AffinePoint::Serialize() const {
  msgpack::sbuffer buffer;
  msgpack::pack(buffer, *this);
  auto sz = buffer.size();
  return {buffer.release(), sz, [](void* ptr) { free(ptr); }};
}

void AffinePoint::Deserialize(ByteContainerView in) {
  auto msg =
      msgpack::unpack(reinterpret_cast<const char*>(in.data()), in.size());
  msgpack::object obj = msg.get();
  obj.convert(*this);
}

std::size_t AffinePoint::HashCode() const {
  return x.Get<size_t>() ^ y.Get<size_t>();
}

std::ostream& operator<<(std::ostream& os, const AffinePoint& point) {
  os << point.ToString();
  return os;
}

}  // namespace yacl::crypto
