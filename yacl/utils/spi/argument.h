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

namespace yacl {

class SpiArg {
 public:
  explicit SpiArg(const std::string &key) : key_(absl::AsciiStrToLower(key)) {}

  template <typename T>
  SpiArg(const std::string &key, T &&value) : key_(absl::AsciiStrToLower(key)) {
    operator=(std::forward<T>(value));
  }

  SpiArg operator=(const char *value) {
    value_ = absl::AsciiStrToLower(std::string(value));
    return *this;
  }

  SpiArg operator=(const std::string &value) {
    value_ = absl::AsciiStrToLower(value);
    return *this;
  }

  template <typename T>
  SpiArg operator=(const T &value) {
    value_ = value;
    return *this;
  }

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

 private:
  std::string key_;
  std::any value_;
};

template <typename T>
class SpiArgKey {
 public:
  explicit SpiArgKey(const std::string &key)
      : key_(absl::AsciiStrToLower(key)) {}

  const std::string &Key() const & { return key_; }

  SpiArg operator=(T &&value) const { return {key_, std::forward<T>(value)}; }
  SpiArg operator=(const T &value) const { return {key_, value}; }

 private:
  std::string key_;
};

// Pre-defined args..
const SpiArgKey<std::string> Lib("lib");

class SpiArgs : public std::map<std::string, SpiArg> {
 public:
  SpiArgs(std::initializer_list<SpiArg> args);

  // Get an argument
  // If this parameter is not set, the default value is returned
  // If the user sets this parameter, but the type is not T, then an exception
  // is thrown
  template <typename T>
  T Get(const SpiArgKey<T> &key, const T &default_value) const {
    auto it = find((key.Key()));
    if (it == end()) {
      return default_value;
    } else {
      return it->second.template Value<T>();
    }
  }

  // Get a required argument.
  // If this parameter is not set, an exception is thrown
  // If the user sets this parameter, but the type is not T, then an exception
  // is thrown
  template <typename T>
  T GetRequired(const SpiArgKey<T> &key) const {
    auto it = find((key.Key()));
    YACL_ENFORCE(it != end(), "Missing required argument {}", key.Key());
    return it->second.template Value<T>();
  }

  // Get an optional argument.
  template <typename T>
  SpiArg GetOptional(const SpiArgKey<T> &key) const {
    auto it = find(key.Key());
    if (it == end()) {
      return SpiArg{key.Key()};
    } else {
      return it->second;
    }
  }
};

}  // namespace yacl
