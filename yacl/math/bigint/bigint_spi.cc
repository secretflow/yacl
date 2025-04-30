// Copyright 2024 Ant Group Co., Ltd.
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

#include "yacl/math/bigint/bigint_spi.h"

#include <cstdlib>

#ifdef BIGNUM_WITH_GMP
#include "yacl/math/bigint/gmp/gmp_lib.h"
#endif
#include "yacl/math/bigint/openssl/openssl_lib.h"
#include "yacl/math/bigint/tommath/tommath_lib.h"

#define REGISTER_BIGNUM_LIBRARY(lib_name, performance, checker, creator)   \
  REGISTER_SPI_LIBRARY_HELPER(BigIntSpiFactoryBase, lib_name, performance, \
                              checker, creator)

namespace yacl::math {

namespace {

void RegisterBigIntLibs() {
#ifdef BIGNUM_WITH_GMP
  REGISTER_BIGNUM_LIBRARY(
      gmp::kLibName, 150,
      [](const std::string&, const SpiArgs&) {
        return gmp::GMPLoader::Instance().IsLoaded();
      },
      [](const std::string&, const SpiArgs&) {
        return std::make_unique<gmp::GmpLib>();
      });
#endif

  REGISTER_BIGNUM_LIBRARY(
      openssl::kLibName, 200,
      [](const std::string&, const SpiArgs&) { return true; },
      [](const std::string&, const SpiArgs&) {
        return std::make_unique<openssl::OpensslLib>();
      });

  REGISTER_BIGNUM_LIBRARY(
      tommath::kLibName, 100,
      [](const std::string&, const SpiArgs&) { return true; },
      [](const std::string&, const SpiArgs&) {
        return std::make_unique<tommath::TomMathLib>();
      });
}

}  // namespace

BigIntSpiFactoryBase& BigIntLibFactory::Instance() {
  RegisterBigIntLibs();
  return BigIntSpiFactoryBase::Instance();
}

const std::shared_ptr<IBigIntLib>& BigIntLibFactory::DefaultBigIntLib() {
  static std::shared_ptr<IBigIntLib> lib;
  if (lib != nullptr) {
    return lib;
  }

  static const char* lib_str = std::getenv("BIGINT_LIB");
  if (lib_str == nullptr) {
    lib = Instance().Create("");
  } else {
    lib = Instance().Create("", ArgLib = lib_str);
  }
  SPDLOG_INFO("The default library used for BigInt operations is {}",
              lib->GetLibraryName());
  return lib;
}

}  // namespace yacl::math
