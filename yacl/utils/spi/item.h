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

#include <any>

#include "absl/types/span.h"

#include "yacl/base/exception.h"

namespace yacl {

template <typename T, typename _ = void>
struct is_container : std::false_type {};

template <typename... Ts>
struct is_container_helper {};

template <typename T>
struct is_container<
    T,
    std::conditional_t<false,
                       is_container_helper<decltype(std::declval<T>().size()),
                                           decltype(std::declval<T>().begin()),
                                           decltype(std::declval<T>().end()),
                                           decltype(std::declval<T>().data())>,
                       void>> : public std::true_type {};

template <typename T>
constexpr bool is_container_v = is_container<T>::value;

template <typename T>
constexpr bool is_const_t =
    std::is_const_v<std::remove_pointer_t<std::remove_reference_t<T>>>;

template <class T>
using remove_cvref_t = std::remove_cv_t<std::remove_reference_t<T>>;

class Item {
 public:
  template <typename T, typename _ = std::enable_if_t<!is_container_v<T>>>
  Item(T&& value) : v_(std::forward<T>(value)) {
    Setup(false, false, false);
  }

  template <typename T, typename _ = std::enable_if_t<is_container_v<T>>>
  static Item Ref(T& c) {
    Item item;
    item.v_ = absl::MakeSpan(c);
    // If T is a reference type then is_const<T>::value is always false. The
    // proper way to check a potentially-reference type for const-ness is to
    // remove the reference: is_const<typename remove_reference<T>::type>
    item.Setup(true, true, is_const_t<decltype(c.data())>);
    return item;
  }

  template <typename T>
  static Item Ref(T* ptr, size_t len) {
    Item item;
    item.v_ = absl::MakeSpan(ptr, len);
    item.Setup(true, true, is_const_t<T>);
    return item;
  }

  template <typename T>
  static Item Take(std::vector<T>&& v) {
    Item item;
    item.v_ = std::move(v);
    item.Setup(true, false, false);
    return item;
  }

  template <typename T>
  std::enable_if_t<!std::is_pointer_v<T>, T>& As() & {
    try {
      return std::any_cast<T&>(v_);
    } catch (const std::bad_any_cast& e) {
      YACL_THROW("Item as lvalue: cannot cast from {} to {}", v_.type().name(),
                 typeid(T).name());
    }
  }

  template <typename T>
  std::enable_if_t<!std::is_pointer_v<T>, T>&& As() && {
    try {
      return std::any_cast<T&&>(std::move(v_));
    } catch (const std::bad_any_cast& e) {
      YACL_THROW("Item as rvalue: cannot cast from {} to {}", v_.type().name(),
                 typeid(T).name());
    }
  }

  template <typename T>
  const T& As() const {
    try {
      return std::any_cast<const T&>(v_);
    } catch (const std::bad_any_cast& e) {
      YACL_THROW("Item as const ref: cannot cast from {} to {}",
                 v_.type().name(), typeid(T).name());
    }
  }

  template <typename T>
  std::enable_if_t<std::is_pointer_v<T>, T> As() {
    try {
      return std::any_cast<std::remove_pointer_t<T>>(&v_);
    } catch (const std::bad_any_cast& e) {
      YACL_THROW("Item as pointer: cannot cast from {} to {}", v_.type().name(),
                 typeid(T).name());
    }
  }

  template <typename T>
  absl::Span<T> AsSpan() {
    YACL_ENFORCE(IsArray(), "Item is not an array");
    if (IsReadOnly()) {
      YACL_ENFORCE(
          is_const_t<T>,
          "This is a read-only item, please use AsSpan<const T> instead");

      // const value -> const T
      if (IsView()) {
        return As<absl::Span<T>>();
      } else {
        // vector
        return absl::MakeSpan(As<std::vector<std::remove_cv_t<T>>>());
      }
    }

    // non-const value -> (const) T
    if (IsView()) {
      return As<absl::Span<std::remove_cv_t<T>>>();
    } else {
      // vector
      return absl::MakeSpan(As<std::vector<std::remove_cv_t<T>>>());
    }
  }

  template <typename T>
  absl::Span<const T> AsSpan() const {
    YACL_ENFORCE(IsArray(), "Item is not an array");
    using RawT = std::remove_cv_t<T>;

    if (IsView()) {
      if (IsReadOnly()) {
        // const value -> const T
        return As<absl::Span<const T>>();
      }
      // non-const value -> const T
      return As<absl::Span<RawT>>();
    } else {
      // vector
      // non-const value -> const T
      return absl::MakeConstSpan(As<std::vector<RawT>>());
    }
  }

  bool HasValue() const noexcept { return v_.has_value(); }

  template <typename T>
  bool IsHoldType() const noexcept {
    return v_.type() == typeid(T);
  }

  bool IsArray() const { return (meta_ & 1) != 0; }
  bool IsView() const { return (meta_ & 2) != 0; }
  bool IsReadOnly() const { return (meta_ & (1 << 2)) != 0; }

  template <typename T>
  bool operator==(const T& other) const {
    static_assert(!std::is_same_v<T, Item>,
                  "Cannot compare to another Item, since the Type info is "
                  "discarded at runtime");
    return HasValue() && IsHoldType<T>() && As<T>() == other;
  }

  template <typename T>
  bool operator!=(const T& other) const {
    return !operator==(other);
  }

  // operations only for array
  template <typename T>
  Item SubSpan(size_t pos, size_t len = absl::Span<T>::npos) {
    YACL_ENFORCE(IsArray(), "You cannot do slice for scalar value");

    if (IsReadOnly() || is_const_t<T>) {
      // force const
      return SubConstSpanImpl<remove_cvref_t<T>>(pos, len);
    }

    return SubSpanImpl<remove_cvref_t<T>>(pos, len);
  }

  template <typename T>
  Item SubSpan(size_t pos, size_t len = absl::Span<T>::npos) const {
    YACL_ENFORCE(IsArray(), "You cannot do slice for scalar value");
    return SubConstSpanImpl<remove_cvref_t<T>>(pos, len);
  }

 private:
  constexpr Item() {}

  constexpr void Setup(bool is_array, bool is_view, bool is_readonly) {
    meta_ |= static_cast<int>((is_array));
    meta_ |= (static_cast<int>(is_view) << 1);
    meta_ |= static_cast<int>(is_readonly) << 2;
  }

  template <typename T>
  Item SubSpanImpl(size_t pos, size_t len) const {
    YACL_ENFORCE(!IsReadOnly(),
                 "Cannot make a read-write subspan of a const span");

    Item item;
    if (IsView()) {
      item.v_ = As<absl::Span<T>>().subspan(pos, len);
    } else {
      // vector
      item.v_ = absl::MakeSpan(As<std::vector<T>>()).subspan(pos, len);
    }

    item.Setup(true, true, false);
    return item;
  }

  template <typename T>
  Item SubConstSpanImpl(size_t pos, size_t len) const {
    Item item;
    if (IsView()) {
      if (IsReadOnly()) {
        // const span -> const span
        item.v_ = As<absl::Span<const T>>().subspan(pos, len);
      } else {
        // span -> const span
        absl::Span<const T> sp = As<absl::Span<T>>().subspan(pos, len);
        item.v_ = sp;
      }
    } else {
      // vector -> const span
      item.v_ = absl::MakeConstSpan(As<std::vector<T>>()).subspan(pos, len);
    }

    item.Setup(true, true, true);
    return item;
  }

  // The format of meta:
  // bit 0 -> is array?  0 - scalar; 1 - array
  // bit 1 -> is view ?  0 - hold value;    1 - ref/view
  // bit 2 -> is const?  0 - rw;     1 - read-only
  uint8_t meta_ = 0;
  std::any v_;
};

}  // namespace yacl
