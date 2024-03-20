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

#include "yacl/crypto/ecc/ecc_spi.h"

#include "absl/strings/ascii.h"

namespace yacl::crypto {

EcGroupFactory &EcGroupFactory::Instance() {
  static EcGroupFactory factory;
  return factory;
}

void EcGroupFactory::Register(const std::string &lib_name, uint64_t performance,
                              const EcCheckerT &checker,
                              const EcCreatorT &creator) {
  SpiFactoryBase<EcGroup>::Register(
      lib_name, performance,
      [checker](const std::string &curve_name, const SpiArgs &) {
        CurveMeta meta;
        try {
          meta = GetCurveMetaByName(curve_name);
        } catch (const yacl::Exception &) {
          return false;
        }
        return checker(meta);
      },
      [creator](const std::string &curve_name, const SpiArgs &) {
        return creator(GetCurveMetaByName(curve_name));
      });
}

}  // namespace yacl::crypto
