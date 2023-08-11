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
#include "yacl/utils/spi/argument.h"

namespace yacl {

// Give config, return SPI instance.
// SPI_T: The type of SPI class, such as EcGroup
template <typename SPI_T>
using SpiCreatorT =
    std::function<std::unique_ptr<SPI_T>(const std::string &, const SpiArgs &)>;

// Given config, return whether feature is supported by this lib.
// Returns: True is supported and false is unsupported.
using SpiCheckerT = std::function<bool(const std::string &, const SpiArgs &)>;

// The base factory of SPI.
// Each SPI can inherit this class for better flexibility
template <typename SPI_T>
class SpiFactoryBase {
 public:
  SpiFactoryBase(const SpiFactoryBase &) = delete;
  SpiFactoryBase(SpiFactoryBase &&) = delete;
  void operator=(const SpiFactoryBase &) = delete;
  void operator=(SpiFactoryBase &&) = delete;

  // Auto selects the best library and creates the spi instance.
  // feature_name: The actual meaning is defined by each SPI. For example,
  // feature_name represents the name of the elliptic curve in ECC SPI, and it
  // represents the name of the phe algorithm in PHE SPI.
  template <typename... T>
  std::unique_ptr<SPI_T> Create(const std::string &feature_name,
                                T &&...extra_args) const {
    SpiArgs args({std::forward<T>(extra_args)...});
    auto lib_name = args.GetOptional(Lib);
    if (!lib_name.HasValue()) {
      for (const auto &perf_item : performance_map_) {
        if (checker_map_.at(perf_item.second)(feature_name, args)) {
          lib_name = perf_item.second;
          break;
        }
        SPDLOG_DEBUG("SPI lib {} does not support feature {}, try next ...",
                     perf_item.second, feature_name);
      }
    }

    YACL_ENFORCE(lib_name.HasValue(),
                 "There is no lib supports {}, please use other feature/args",
                 feature_name);
    YACL_ENFORCE(creator_map_.count(lib_name.Value<std::string>()) > 0,
                 "Create {} instance fail, spi lib not found",
                 lib_name.Value<std::string>());

    return creator_map_.at(lib_name.Value<std::string>())(feature_name, args);
  }

  // List all registered libraries
  std::vector<std::string> ListLibraries() const {
    std::vector<std::string> res;
    res.reserve(creator_map_.size());
    for (const auto &[key, _] : creator_map_) {
      res.push_back(key);
    }
    return res;
  }

  // List libraries that support this feature
  template <typename... T>
  std::vector<std::string> ListLibraries(const std::string &feature_name,
                                         T &&...extra_args) const {
    std::vector<std::string> res;
    SpiArgs args({std::forward<T>(extra_args)...});
    for (const auto &item : checker_map_) {
      if (!item.second(feature_name, args)) {
        continue;
      }
      res.push_back(item.first);
    }
    return res;
  }

  void Register(const std::string &lib_name, uint64_t performance,
                const SpiCheckerT &checker, const SpiCreatorT<SPI_T> &creator) {
    auto lib_key = absl::AsciiStrToLower(lib_name);

    YACL_ENFORCE(creator_map_.count(lib_key) == 0,
                 "SPI lib name conflict, {} already exist", lib_key);
    while (performance_map_.count(performance) > 0) {
      ++performance;
    }

    performance_map_.insert({performance, lib_key});
    checker_map_.insert({lib_key, checker});
    creator_map_.insert({lib_key, creator});
  }

 protected:
  SpiFactoryBase() = default;

 private:
  std::map<uint64_t, std::string, std::greater<>> performance_map_;
  std::map<std::string, SpiCreatorT<SPI_T>> creator_map_;
  std::map<std::string, SpiCheckerT> checker_map_;
};

// Helper class for REGISTER_SPI_LIBRARY_HELPER macro
// FACTORY_T: The subclass of SpiFactoryBase
template <typename FACTORY_T>
class Registration {
 public:
  /// Register an spi library
  /// \param lib_name library name, e.g. openssl
  /// \param performance the estimated performance of this lib, bigger is
  /// better
  template <typename CheckerT, typename CreatorT>
  Registration(const std::string &lib_name, uint64_t performance,
               const CheckerT &checker, const CreatorT &creator) {
    FACTORY_T::Instance().Register(lib_name, performance, checker, creator);
  }
};

// The helper macro for factory registration
#define CONCAT_IMPL(x, y) x##y
#define CONCAT(x, y) CONCAT_IMPL(x, y)
#define REGISTER_SPI_LIBRARY_HELPER(factory_t, lib_name, performance, checker, \
                                    creator)                                   \
  static Registration<factory_t> CONCAT(registration_spi_, __COUNTER__)(       \
      lib_name, performance, checker, creator)
}  // namespace yacl
