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
#include <atomic>
#include <cstdint>
#include <utility>
#include <vector>

#include "absl/types/span.h"

#include "yacl/base/exception.h"
#include "yacl/utils/parallel.h"

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

// If T is a reference type, then is_const<T>::value is always false. The
// proper way to check a potential-reference type for const-ness is to
// remove the reference: is_const<typename remove_reference<T>::type>
template <typename T>
constexpr bool is_const_v =
    std::is_const_v<std::remove_pointer_t<std::remove_reference_t<T>>>;

template <class T>
using remove_cvref_t = std::remove_cv_t<std::remove_reference_t<T>>;

enum class OperandType : int {
  Scalar2Scalar = 0b00,
  Scalar2Vector = 0b01,
  Vector2Scalar = 0b10,
  Vector2Vector = 0b11,
};

class Item {
 public:
  // Take or copy scalar
  template <typename T, typename _ = std::enable_if_t<!is_container_v<T>>>
  /* implicit */ constexpr Item(T&& value) : v_(std::forward<T>(value)) {
    Setup(false, false, false);
  }

  // Ref a vector/span
  template <typename T, typename _ = std::enable_if_t<is_container_v<T>>>
  static Item Ref(T& c) {
    return Item{absl::MakeSpan(c)};
  }

  template <typename T>
  static Item Ref(T* ptr, size_t len) {
    return Item{absl::MakeSpan(ptr, len)};
  }

  // Take vector
  template <typename T>
  static Item Take(std::vector<T>&& v) {
    return Item{std::move(v)};
  }

  Item(const Item&) = default;
  Item(Item&&) = default;
  Item& operator=(const Item&) = default;
  Item& operator=(Item&&) = default;
  virtual ~Item() = default;

  template <typename T>
  explicit operator T() const& {
    YACL_ENFORCE(v_.type() == typeid(T), "Type mismatch: convert {} to {} fail",
                 v_.type().name(), typeid(T).name());
    return As<T>();
  }

  template <typename T>
  explicit operator T() && {
    YACL_ENFORCE(v_.type() == typeid(T),
                 "Type mismatch: convert rvalue {} to {} fail",
                 v_.type().name(), typeid(T).name());
    return As<T&&>();
  }

  template <typename T>
  std::enable_if_t<!std::is_pointer_v<T>, T>& As() & {
    try {
      return std::any_cast<T&>(v_);
    } catch (const std::bad_any_cast& e) {
      YACL_THROW_WITH_STACK(
          "{}, Item as lvalue: cannot cast from {} to {}, please use 'c++filt "
          "-t <symbol>' tool to see a human-readable name.",
          ToString(), v_.type().name(), typeid(T&).name());
    }
  }

  template <typename T>
  std::enable_if_t<!std::is_pointer_v<T>, T>&& As() && {
    try {
      return std::any_cast<T&&>(std::move(v_));
    } catch (const std::bad_any_cast& e) {
      YACL_THROW_WITH_STACK(
          "{}, Item as rvalue: cannot cast from {} to {}, please use 'c++filt "
          "-t <symbol>' tool to see a human-readable name",
          ToString(), v_.type().name(), typeid(T&&).name());
    }
  }

  template <typename T>
  const T& As() const {
    try {
      return std::any_cast<const T&>(v_);
    } catch (const std::bad_any_cast& e) {
      YACL_THROW_WITH_STACK(
          "{}, Item as a const ref: cannot cast from {} to {}, please use "
          "'c++filt -t <symbol>' tool to see a human-readable name. ",
          ToString(), v_.type().name(), typeid(const T&).name());
    }
  }

  template <typename T>
  std::enable_if_t<std::is_pointer_v<T>, T> As() {  // As a pointer
    try {
      return std::any_cast<std::remove_pointer_t<T>>(&v_);
    } catch (const std::bad_any_cast& e) {
      YACL_THROW_WITH_STACK(
          "{}, Item as a pointer: cannot cast from {} to {}, please use "
          "'c++filt -t <symbol>' tool to see a human-readable name",
          ToString(), v_.type().name(),
          typeid(std::remove_pointer_t<T>).name());
    }
  }

  template <typename T>
  absl::Span<T> AsSpan() {
    if (!IsArray()) {
      // single element as span
      YACL_ENFORCE(!IsReadOnly(), "Single const T is not supported now");

      return absl::MakeSpan(&As<T>(), 1);
    }

    using RawT = std::remove_cv_t<T>;

    // const array case
    if (IsReadOnly()) {
      YACL_ENFORCE(
          is_const_v<T>,
          "This is a read-only item, please use AsSpan<const T> instead");

      // const value -> const T
      if (IsView()) {
        return As<absl::Span<T>>();
      } else {
        // vector
        return absl::MakeSpan(As<std::vector<RawT>>());
      }
    }

    // non-const array case
    if (IsView()) {
      // span
      return As<absl::Span<RawT>>();
    } else {
      // vector
      return absl::MakeSpan(As<std::vector<RawT>>());
    }
  }

  template <typename T>
  absl::Span<const T> AsSpan() const {
    if (!IsArray()) {
      // single element as span
      return absl::MakeSpan(&As<T>(), 1);
    }

    using RawT = std::remove_cv_t<T>;

    if (IsView()) {
      if (IsReadOnly()) {
        // const value -> const T
        return As<absl::Span<const T>>();
      }
      // non-const value -> const T
      return As<absl::Span<RawT>>();
    } else {
      static_assert(!std::is_same_v<bool, RawT>,
                    "Call AsSpan<bool> on a vector item is not allowed");

      // vector
      // non-const value -> const T
      return absl::MakeConstSpan(As<std::vector<RawT>>());
    }
  }

  template <typename T>
  absl::Span<T> ResizeAndSpan(size_t expected_size) {
    auto sp = AsSpan<T>();
    if (sp.size() == expected_size) {
      return sp;
    }

    // size doesn't match, now we try to resize
    YACL_ENFORCE(IsArray() && !IsView() && !IsReadOnly(),
                 "Resize item fail, actual size={}, resize={}, item_info: {}",
                 sp.size(), expected_size, ToString());
    auto& vec = As<std::vector<T>>();
    vec.resize(expected_size);
    return absl::MakeSpan(vec);
  }

  bool HasValue() const noexcept { return v_.has_value(); }

  // Check the type that directly stored, which is, container type + data type
  template <typename T>
  bool WrappedTypeIs() const noexcept {
    return v_.type() == typeid(T);
  }

  // Check the underlying date type regardless of the wrapping container type
  template <typename T>
  bool DataTypeIs() const noexcept {
    if (IsArray()) {
      return WrappedTypeIs<std::vector<T>>() ||
             WrappedTypeIs<absl::Span<T>>() ||
             WrappedTypeIs<absl::Span<const T>>();
    } else {
      return WrappedTypeIs<T>();
    }
  }

  bool IsArray() const { return (meta_ & 1) != 0; }
  bool IsView() const { return (meta_ & 2) != 0; }
  bool IsReadOnly() const { return (meta_ & (1 << 2)) != 0; }

  template <typename T>
  bool operator==(const T& other) const {
    static_assert(!std::is_same_v<T, Item>,
                  "Cannot compare to another Item, since the Type info is "
                  "discarded at runtime");
    return HasValue() && WrappedTypeIs<T>() && As<T>() == other;
  }

  template <typename T>
  bool operator!=(const T& other) const {
    return !operator==(other);
  }

  // is every element in item equals "element"
  template <typename T>
  bool IsAll(const T& element) const;

  OperandType operator,(const Item& other) const {
    return static_cast<OperandType>(((meta_ & 1) << 1) | (other.meta_ & 1));
  }

  // operations only for array
  template <typename T>
  Item SubItem(size_t pos, size_t len = absl::Span<T>::npos) {
    YACL_ENFORCE(IsArray(), "You cannot do slice for scalar value");

    if (IsReadOnly() || is_const_v<T>) {
      // force const
      return SubConstItemImpl<remove_cvref_t<T>>(pos, len);
    }

    return SubItemImpl<remove_cvref_t<T>>(pos, len);
  }

  template <typename T>
  Item SubItem(size_t pos, size_t len = absl::Span<T>::npos) const {
    YACL_ENFORCE(IsArray(), "You cannot do slice for scalar value");
    return SubConstItemImpl<remove_cvref_t<T>>(pos, len);
  }

  virtual std::string ToString() const;

 protected:
  template <typename T>
  constexpr explicit Item(const absl::Span<T>& span) : v_(span) {
    Setup(true, true, is_const_v<T>);
  }

  template <typename T>
  constexpr explicit Item(std::vector<T>&& vec) : v_(std::move(vec)) {
    Setup(true, false, false);
  }

  template <int slot, int len = 1>
  constexpr void SetSlot(uint8_t value) {
    static_assert(slot >= 3 && slot + len <= sizeof(meta_) * 8);
    constexpr auto mask = ((static_cast<decltype(meta_)>(1) << len) - 1)
                          << slot;
    meta_ &= ~mask;  // set target bits to zero
    meta_ |= ((value << slot) & mask);
  }

  template <int slot, int len = 1>
  constexpr uint8_t GetSlot() const {
    static_assert(slot >= 3 && slot + len <= sizeof(meta_) * 8);
    return (meta_ >> slot) & ((static_cast<decltype(meta_)>(1) << len) - 1);
  }

 private:
  constexpr Item() {}

  constexpr void Setup(bool is_array, bool is_view, bool is_readonly) {
    meta_ |= static_cast<int>((is_array));
    meta_ |= (static_cast<int>(is_view) << 1);
    meta_ |= static_cast<int>(is_readonly) << 2;
  }

  // For developer: This is not a const func. DO NOT add const qualifier
  template <typename T>
  Item SubItemImpl(size_t pos, size_t len) {
    YACL_ENFORCE(!IsReadOnly(),
                 "Cannot make a read-write sub-item of a const span");

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
  Item SubConstItemImpl(size_t pos, size_t len) const {
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

  template <typename T>
  bool IsAllSameTo(absl::Span<const T> real, const T& expected) const {
    std::atomic<bool> res = true;
    yacl::parallel_for(0, real.length(), [&](int64_t beg, int64_t end) {
      for (int64_t i = beg; i < end; ++i) {
        if (!res) {
          return;
        }

        if (real[i] != expected) {
          res.store(false);
          return;
        }
      }
    });
    return res.load();
  }

  std::any v_;
  // The format of meta:
  // bit 0 -> is array?  0 - scalar; 1 - array
  // bit 1 -> is view ?  0 - hold value;    1 - ref/view
  // bit 2 -> is const?  0 - rw;     1 - read-only
  uint8_t meta_ = 0;
};

std::ostream& operator<<(std::ostream& os, const Item& a);

template <>
bool Item::IsAll(const bool& element) const;

template <typename T>
bool Item::IsAll(const T& element) const {
  if (!HasValue()) {
    return false;
  }
  return IsAllSameTo(AsSpan<T>(), element);
}

}  // namespace yacl
