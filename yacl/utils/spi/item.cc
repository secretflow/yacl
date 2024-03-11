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

#define TRY_TYPE(type)                                        \
  if (t == typeid(type)) {                                    \
    return fmt::to_string(std::any_cast<type>(v));            \
  }                                                           \
  if (t == typeid(absl::Span<type>)) {                        \
    const auto &c = std::any_cast<absl::Span<type>>(v);       \
    return fmt::to_string(fmt::join(c, ", "));                \
  }                                                           \
  if (t == typeid(absl::Span<const type>)) {                  \
    const auto &c = std::any_cast<absl::Span<const type>>(v); \
    return fmt::to_string(fmt::join(c, ", "));                \
  }                                                           \
  if (t == typeid(std::vector<type>)) {                       \
    const auto &c = std::any_cast<std::vector<type>>(v);      \
    return fmt::to_string(fmt::join(c, ", "));                \
  }

std::string TryRead(const std::any &v) {
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

template <>
bool Item::IsAll(const bool &element) const {
  if (!HasValue()) {
    return false;
  }

  if (!IsArray()) {
    return As<bool>() == element;
  }

  if (IsView()) {
    absl::Span<const bool> real =
        IsReadOnly() ? As<absl::Span<const bool>>() : As<absl::Span<bool>>();
    return IsAllSameTo(real, element);
  }

  auto &real = As<std::vector<bool>>();
  for (const auto &item : real) {
    if (item != element) {
      return false;
    }
  }
  return true;
}

std::string Item::ToString() const {
  if (IsArray()) {
    return fmt::format("{} Item, element_type={}, {}, Content=[{}]",
                       IsView() ? "Span" : "Vector", v_.type().name(),
                       IsReadOnly() ? "RO" : "RW", TryRead(v_));
  } else {
    return fmt::format("Scalar item, type={}, {}, Content={}", v_.type().name(),
                       IsReadOnly() ? "RO" : "RW", TryRead(v_));
  }
}

std::ostream &operator<<(std::ostream &os, const Item &a) {
  return os << a.ToString();
}

}  // namespace yacl
