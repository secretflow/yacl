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

#include "yacl/utils/spi/item.h"

#include "yacl/math/mpint/mp_int.h"

namespace yacl {

namespace {

std::string TryRead(const std::any &v) {
#define TRY_TYPE(type)                             \
  if (t == typeid(type)) {                         \
    return fmt::to_string(std::any_cast<type>(v)); \
  }

  const auto &t = v.type();
  TRY_TYPE(bool);
  TRY_TYPE(int8_t);
  TRY_TYPE(int16_t);
  TRY_TYPE(int32_t);
  TRY_TYPE(int64_t);  // mac-m1 doesn't support int128
  TRY_TYPE(uint8_t);
  TRY_TYPE(uint16_t);
  TRY_TYPE(uint32_t);
  TRY_TYPE(uint64_t);
  TRY_TYPE(double);
  TRY_TYPE(float);
  TRY_TYPE(char);
  TRY_TYPE(unsigned char);
  TRY_TYPE(math::MPInt);  // MPInt is a first-class citizen in SPI
  return "<object>";
}

}  // namespace

std::string Item::ToString() const {
  if (IsArray()) {
    return fmt::format("{} Item, element_type={}, RO={}",
                       IsView() ? "Span" : "Vector", v_.type().name(),
                       IsReadOnly());
  } else {
    return fmt::format("Scalar item, type={}, RO={}, Content={}",
                       v_.type().name(), IsReadOnly(), TryRead(v_));
  }
}

std::ostream &operator<<(std::ostream &os, const Item &a) {
  return os << a.ToString();
}

}  // namespace yacl
