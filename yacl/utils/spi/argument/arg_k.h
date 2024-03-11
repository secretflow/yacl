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

#include "absl/strings/ascii.h"
#include "spdlog/spdlog.h"

#include "yacl/utils/spi/argument/arg_kv.h"
#include "yacl/utils/spi/argument/util.h"

namespace yacl {

template <typename T>
class SpiArgKey {
 public:
  using ValueType = T;

  explicit SpiArgKey(const std::string &key) : key_(util::ToSnakeCase(key)) {}

  const std::string &Key() const & { return key_; }

  // If value is a string, it will be automatically converted to lowercase
  SpiArg operator=(T &&value) const { return {key_, std::forward<T>(value)}; }
  SpiArg operator=(const T &value) const { return {key_, value}; }

 private:
  std::string key_;
};

// helper macros

#define DEFINE_ARG(T, ArgName) const yacl::SpiArgKey<T> Arg##ArgName(#ArgName)

#define DECLARE_ARG(T, ArgName)                                          \
  extern __attribute__((visibility("default"))) const yacl::SpiArgKey<T> \
      Arg##ArgName

// define an arg
#define DEFINE_ARG_bool(ArgName) DEFINE_ARG(bool, ArgName)
#define DEFINE_ARG_int(ArgName) DEFINE_ARG(int, ArgName)
#define DEFINE_ARG_uint(ArgName) DEFINE_ARG(uint, ArgName)
#define DEFINE_ARG_int64(ArgName) DEFINE_ARG(int64_t, ArgName)
#define DEFINE_ARG_uint64(ArgName) DEFINE_ARG(uint64_t, ArgName)
#define DEFINE_ARG_double(ArgName) DEFINE_ARG(double, ArgName)
// Note: The arg value will be automatically converted to lowercase
#define DEFINE_ARG_string(ArgName) DEFINE_ARG(std::string, ArgName)

// declare an arg
#define DECLARE_ARG_bool(ArgName) DECLARE_ARG(bool, ArgName)
#define DECLARE_ARG_int(ArgName) DECLARE_ARG(int, ArgName)
#define DECLARE_ARG_uint(ArgName) DECLARE_ARG(uint, ArgName)
#define DECLARE_ARG_int64(ArgName) DECLARE_ARG(int64_t, ArgName)
#define DECLARE_ARG_uint64(ArgName) DECLARE_ARG(uint64_t, ArgName)
#define DECLARE_ARG_double(ArgName) DECLARE_ARG(double, ArgName)
// Note: The arg value will be automatically converted to lowercase
#define DECLARE_ARG_string(ArgName) DECLARE_ARG(std::string, ArgName)

}  // namespace yacl
