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
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>

#include "absl/strings/ascii.h"
#include "spdlog/spdlog.h"

#include "yacl/base/exception.h"
#include "yacl/utils/spi/argument/util.h"

namespace yacl {

class SpiArg {
 public:
  explicit SpiArg(const std::string &key) : key_(util::ToSnakeCase(key)) {}

  // If value is a string, it will be automatically converted to lowercase
  template <typename T>
  SpiArg(const std::string &key, T &&value) : key_(util::ToSnakeCase(key)) {
    operator=(std::forward<T>(value));
  }

  template <typename T>
  SpiArg &operator=(const T &value) {
    value_ = value;
    return *this;
  }

  // Specialized functions of operator=<T>
  // If value is a string, it will be automatically converted to lowercase
  SpiArg &operator=(const char *value);
  SpiArg &operator=(const std::string &value);

  const std::string &Key() const;
  bool HasValue() const;

  template <typename T>
  T Value() const {
    try {
      return std::any_cast<T>(value_);
    } catch (const std::bad_any_cast &e) {
      YACL_THROW("Get SPI arg {}: Cannot cast from {} to {}", key_,
                 value_.type().name(), typeid(T).name());
    }
  }

  std::string ToString() const;

 private:
  std::string key_;
  std::any value_;
};

inline auto format_as(const SpiArg &arg) { return arg.ToString(); }

}  // namespace yacl
