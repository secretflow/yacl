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

#pragma once

#include "yacl/math/bigint/bigint_lib.h"

namespace yacl::math::openssl {

static inline const char* kLibName = "openssl";

class OpensslLib : public IBigIntLib {
 public:
  std::string GetLibraryName() const override { return kLibName; }

  BigIntVar NewBigInt() const override;
  BigIntVar NewBigInt(size_t reserved_bits) const override;
  BigIntVar NewBigInt(const std::string& str, int base) const override;

  BigIntVar RandomExactBits(size_t bit_size) const override;
  BigIntVar RandomMonicExactBits(size_t bit_size) const override;

  BigIntVar RandPrimeOver(size_t bit_size,
                          PrimeType prime_type = PrimeType::BBS) const override;

  std::unique_ptr<MontgomerySpace> CreateMontgomerySpace(
      const BigIntVar& mod) const override;
};

}  // namespace yacl::math::openssl
