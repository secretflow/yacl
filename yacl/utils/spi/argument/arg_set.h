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

#include "yacl/utils/spi/argument/arg_k.h"

namespace yacl {

class SpiArgs : public std::map<std::string, SpiArg> {
 public:
  SpiArgs(std::initializer_list<SpiArg> args);

  // Get an argument
  // If this parameter is not set, the default value is returned
  // If the user sets this parameter, but the type is not T, then an exception
  // is thrown
  template <typename T>
  T Get(const SpiArgKey<T> &key,
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
  auto GetRequired(const SpiArgKey<T> &key) const ->
      typename SpiArgKey<T>::ValueType {
    auto it = find((key.Key()));
    YACL_ENFORCE(it != end(), "Missing required argument {}", key.Key());
    return it->second.template Value<T>();
  }

  // Get an optional argument.
  // After getting the SpiArg, you can use SpiArg.HasValue() to check if it
  // contains a value
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
