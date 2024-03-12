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

#include <optional>

#include "yacl/utils/spi/argument/arg_k.h"

namespace yacl {

class SpiArgs : private std::map<std::string, SpiArg> {
 public:
  SpiArgs(std::initializer_list<SpiArg> args);

  void Insert(const SpiArg &arg);

  using std::map<std::string, SpiArg>::size;
  using std::map<std::string, SpiArg>::empty;
  using std::map<std::string, SpiArg>::begin;
  using std::map<std::string, SpiArg>::cbegin;
  using std::map<std::string, SpiArg>::end;
  using std::map<std::string, SpiArg>::cend;

  // Get an argument
  // If this parameter is not set, the default value is returned
  // If the user sets this parameter, but the type is not T, then an exception
  // is thrown
  template <typename T>
  T GetOrDefault(const SpiArgKey<T> &key,
                 const typename SpiArgKey<T>::ValueType &default_value) const {
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
  // After getting the SpiArg, you can use SpiArg.HasValue() to check if it
  // contains a value
  template <typename T>
  std::optional<T> GetOptional(const SpiArgKey<T> &key) const {
    auto it = find(key.Key());
    if (it == end()) {
      return {};
    } else {
      return it->second.template Value<T>();
    }
  }

  // Check if key exists
  template <typename T>
  bool Exist(const SpiArgKey<T> &key) const {
    return find(key.Key()) != end();
  }

  std::string ToString() const;
};

inline auto format_as(const SpiArgs &arg) { return arg.ToString(); }

}  // namespace yacl
