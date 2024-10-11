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
#include <vector>

#include "absl/strings/ascii.h"
#include "spdlog/spdlog.h"

#include "yacl/base/exception.h"
#include "yacl/utils/spi/argument/argument.h"

namespace yacl {

// Give config, return SPI instance.
// SPI_T: The type of SPI class, such as EcGroup
template <typename SPI_T>
using SpiCreatorT =
    std::function<std::unique_ptr<SPI_T>(const std::string &, const SpiArgs &)>;

// Given config, return whether feature is supported by this lib.
// Returns: True is supported and false is unsupported.
using SpiCheckerT = std::function<bool(const std::string &, const SpiArgs &)>;

template <typename SPI_T>
struct SpiLibMeta {
  int64_t performance;

  // pointer to Ckeck(...) function
  SpiCheckerT Check;
  // pointer to Create(...) function
  SpiCreatorT<SPI_T> Create;
};

// The base factory of SPI.
// Each SPI can inherit this class for better flexibility
template <typename SPI_T>
class SpiFactoryBase {
 public:
  SpiFactoryBase(const SpiFactoryBase &) = delete;
  SpiFactoryBase(SpiFactoryBase &&) = delete;
  void operator=(const SpiFactoryBase &) = delete;
  void operator=(SpiFactoryBase &&) = delete;

  // Create a library instance
  //
  // If `extra_args` explicitly specifies the library to be created (with
  // ArgLib=xxx_name), the factory checks if the library supports the input
  // parameters; if it does, it creates an instance of the library.
  // If `extra_args` does not specify a library name, the factory automatically
  // selects the highest-performing library that meets the parameter
  // requirements and creates an instance.
  //
  // 中文(translation)：
  // 如果extra_args明确指定了要创建的库，则工厂检查该库是否支持输入参数，如果支持则创建库实例。
  // 如果extra_args未指定库名称，则工厂自动选择性能最高，且满足参数要求的库并创建实例
  //
  // @param: feature_name: The actual meaning is defined by each SPI. For
  //   example, feature_name represents the name of the elliptic curve in ECC
  //   SPI, and it represents the name of the HE algorithm in HE SPI.
  template <typename... T>
  std::unique_ptr<SPI_T> Create(const std::string &feature_name,
                                T &&...extra_args) const {
    return CreateFromArgPkg(feature_name, {std::forward<T>(extra_args)...});
  }

  std::unique_ptr<SPI_T> CreateFromArgPkg(const std::string &feature_name,
                                          const SpiArgs &args) const {
    auto lib_name = args.GetOptional(ArgLib);
    if (!lib_name) {
      // no lib name, auto select best lib
      for (const auto &perf_item : performance_map_) {
        if (libs_map_.at(perf_item.second).Check(feature_name, args)) {
          lib_name = perf_item.second;
          break;
        }
        SPDLOG_DEBUG("SPI lib {} does not support feature {}, try next ...",
                     perf_item.second, feature_name);
      }

      // check the target lib is founded after for-loop
      YACL_ENFORCE(
          lib_name,
          "There are no lib supports {}, please use other feature/args",
          feature_name);
    } else {
      // The user has specified lib
      auto lib_it = libs_map_.find(*lib_name);
      YACL_ENFORCE(lib_it != libs_map_.end(), "Lib {} not exist", *lib_name);
      YACL_ENFORCE(lib_it->second.Check(feature_name, args),
                   "Lib {} does not support feature {} or args", *lib_name,
                   feature_name);
    }

    try {
      return libs_map_.at(*lib_name).Create(feature_name, args);
    } catch (const std::exception &ex) {
      SPDLOG_ERROR(
          "SPI: Create Lib {} fail, Input args are: {}, Detail message:\n{}",
          *lib_name, args.ToString(), ex.what());
      throw;
    }
  }

  // List all registered libraries
  std::vector<std::string> ListLibraries() const {
    std::vector<std::string> res;
    res.reserve(libs_map_.size());
    for (const auto &[key, _] : libs_map_) {
      res.push_back(key);
    }
    return res;
  }

  // List libraries that support this feature
  //
  // * If `extra_args` explicitly specifies the library to create (for example,
  // ArgLib=xxx_name), then the method will check if the library supports the
  // specified parameters. If it does, it returns a list containing only that
  // library; otherwise, it returns an empty list.
  // * If `extra_args` does not specify a library name, then the method returns
  // the names of all libraries that satisfy the parameter requirements.
  template <typename... T>
  std::vector<std::string> ListLibraries(const std::string &feature_name,
                                         T &&...extra_args) const {
    return ListLibrariesFromArgPkg(feature_name,
                                   {std::forward<T>(extra_args)...});
  }

  std::vector<std::string> ListLibrariesFromArgPkg(
      const std::string &feature_name, const SpiArgs &args) const {
    std::vector<std::string> res;
    auto lib_name = args.GetOptional(ArgLib);
    for (const auto &item : libs_map_) {
      // Check ArgLib limit
      if (lib_name && *lib_name != item.first) {
        continue;
      }
      // Check other args limit
      if (!item.second.Check(feature_name, args)) {
        continue;
      }
      res.push_back(item.first);
    }
    return res;
  }

  void Register(const std::string &lib_name, int64_t performance,
                const SpiCheckerT &checker, const SpiCreatorT<SPI_T> &creator) {
    auto lib_key = absl::AsciiStrToLower(lib_name);

    YACL_ENFORCE(libs_map_.count(lib_key) == 0,
                 "SPI lib name conflict, {} already exist", lib_key);

    performance_map_.insert({performance, lib_key});
    libs_map_.insert({lib_key, {performance, checker, creator}});
  }

 protected:
  SpiFactoryBase() = default;

 private:
  // performance/priority -> lib name
  std::multimap<uint64_t, std::string, std::greater<>> performance_map_;
  // lib name -> lib meta (include factory)
  std::map<std::string, SpiLibMeta<SPI_T>> libs_map_;
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
  Registration(const std::string &lib_name, int64_t performance,
               const CheckerT &checker, const CreatorT &creator) {
    FACTORY_T::Instance().Register(lib_name, performance, checker, creator);
  }
};

// The helper macro for factory registration
#define CONCAT_IMPL(x, y) x##y
#define CONCAT(x, y) CONCAT_IMPL(x, y)
#define REGISTER_SPI_LIBRARY_HELPER(factory_t, lib_name, performance, checker, \
                                    creator)                                   \
  static ::yacl::Registration<factory_t> CONCAT(                               \
      registration_spi_, __COUNTER__)(lib_name, performance, checker, creator)
}  // namespace yacl
