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

#include <functional>
#include <memory>
#include <type_traits>
#include <variant>

#include "yacl/base/exception.h"

namespace yacl::crypto {

template <typename T>
struct is_variant : std::false_type {};

template <typename... Args>
struct is_variant<std::variant<Args...>> : std::true_type {};

template <typename T>
inline constexpr bool is_variant_v = is_variant<T>::value;

class AnyPtr {
 public:
  AnyPtr(void* ptr, std::function<void(void*)> deleter)
      : ptr_(ptr, std::move(deleter)) {}

  explicit AnyPtr(const std::shared_ptr<void>& ptr) : ptr_(ptr) {}

  template <typename T>
  inline const T* get() const& {
    return reinterpret_cast<const T*>(ptr_.get());
  }

  template <typename T>
  inline T* get() & {
    return reinterpret_cast<T*>(ptr_.get());
  }

 private:
  std::shared_ptr<void> ptr_;
};

template <typename T, class... Args>
AnyPtr MakeShared(Args&&... args) {
  return AnyPtr(std::make_shared<T>(std::forward<Args>(args)...));
}

template <typename To>
inline To* CastAny(AnyPtr& ptr) {
  return ptr.get<To>();
}

//
// Cast Funcs for casting a variant to an underlying specific type
//
template <typename To, typename From,
          std::enable_if_t<is_variant_v<From>, bool> = true>
inline const To* CastAny(const From& p) {
  YACL_ENFORCE(std::holds_alternative<AnyPtr>(p),
               "Unsupported type, expected AnyPtr, real type "
               "index is {}",
               p.index());
  return std::get<AnyPtr>(p).template get<To>();
}

template <typename To, typename From,
          std::enable_if_t<is_variant_v<From>, bool> = true>
inline To* CastAny(From& p) {
  YACL_ENFORCE(std::holds_alternative<AnyPtr>(p),
               "Unsupported type, expected AnyPtr, real type "
               "index is {}",
               p.index());

  return std::get<AnyPtr>(p).template get<To>();
}

template <typename To, typename From,
          std::enable_if_t<is_variant_v<From>, bool> = true>
inline To* CastAny(From* p) {
  CheckNotNull(p);
  YACL_ENFORCE(std::holds_alternative<AnyPtr>(*p),
               "Unsupported type, expected AnyPtr, real type "
               "index is {}",
               p->index());

  return std::get<AnyPtr>(*p).template get<To>();
}

}  // namespace yacl::crypto
