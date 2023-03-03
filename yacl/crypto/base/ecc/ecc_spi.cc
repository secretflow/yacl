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

#include "yacl/crypto/base/ecc/ecc_spi.h"

#include "absl/strings/ascii.h"
#include "spdlog/spdlog.h"

namespace yacl::crypto {

namespace {

// The construction order of global static variables is not fixed. In order to
// ensure that the variables can be accessed at any time, we wrap the 'map'
// variable within the GStore type to ensure that the variables must have been
// constructed before accessing.
struct GStore {
  static auto& PerformanceMap() {
    static std::map<uint64_t, std::string, std::greater<>> kPerformanceMap;
    return kPerformanceMap;
  }

  static auto& CheckerMap() {
    static std::map<std::string, EcCheckerT> kCheckerMap;
    return kCheckerMap;
  }

  static auto& CreatorMap() {
    static std::map<std::string, EcCreatorT> kCreatorMap;
    return kCreatorMap;
  }
};

}  // namespace

crypto::EcGroupFactory::Registration::Registration(const std::string& lib_name,
                                                   uint64_t performance,
                                                   const EcCheckerT& checker,
                                                   const EcCreatorT& creator) {
  auto lib_key = absl::AsciiStrToLower(lib_name);
  YACL_ENFORCE(GStore::CreatorMap().count(lib_key) == 0,
               "Ec lib name conflict, {} already exist", lib_key);
  while (GStore::PerformanceMap().count(performance) > 0) {
    ++performance;
  }

  GStore::PerformanceMap().insert({performance, lib_key});
  GStore::CheckerMap().insert({lib_key, checker});
  GStore::CreatorMap().insert({lib_key, creator});

  SPDLOG_INFO("Ec lib {} registered.", lib_name);
}

std::vector<std::string> EcGroupFactory::ListEcLibraries() {
  std::vector<std::string> res;
  res.reserve(GStore::CreatorMap().size());
  for (const auto& [key, _] : GStore::CreatorMap()) {
    res.push_back(key);
  }
  return res;
}

std::vector<std::string> EcGroupFactory::ListEcLibraries(
    const CurveName& ec_name) {
  CurveMeta meta;
  try {
    meta = GetCurveMetaByName(ec_name);
  } catch (const yacl::Exception&) {
    return {};
  }

  std::vector<std::string> res;
  for (const auto& item : GStore::CheckerMap()) {
    if (!item.second(meta)) {
      continue;
    }
    res.push_back(item.first);
  }
  return res;
}

std::unique_ptr<EcGroup> EcGroupFactory::Create(const CurveName& ec_name) {
  auto meta = GetCurveMetaByName(ec_name);
  for (const auto& perf_item : GStore::PerformanceMap()) {
    if (!GStore::CheckerMap().at(perf_item.second)(meta)) {
      SPDLOG_DEBUG("Ec lib {} do not support curve {}, msg={}, try next ...",
                   perf_item.second, ec_name, ex.what());
      continue;
    }
    return GStore::CreatorMap().at(perf_item.second)(meta);
  }
  YACL_THROW("There is no lib supports {}, please use others curves", ec_name);
}

std::unique_ptr<EcGroup> EcGroupFactory::Create(const CurveName& ec_name,
                                                const std::string& lib_name) {
  auto lib_key = absl::AsciiStrToLower(lib_name);
  YACL_ENFORCE(GStore::CreatorMap().count(lib_key) > 0,
               "Create CurveGroup fail, EC lib [{}] not found", lib_key);
  return GStore::CreatorMap().at(lib_key)(GetCurveMetaByName(ec_name));
}

}  // namespace yacl::crypto
