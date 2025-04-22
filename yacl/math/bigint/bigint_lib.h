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

#include "yacl/math/bigint/mont_space.h"

namespace yacl::math {

class IBigIntLib {
 public:
  virtual ~IBigIntLib() = default;

  virtual std::string GetLibraryName() const = 0;

  virtual BigIntVar NewBigInt() const = 0;
  virtual BigIntVar NewBigInt(size_t reserved_bits) const = 0;
  virtual BigIntVar NewBigInt(const std::string& str, int base) const = 0;

  // Generate an exact bit_size random number, the msb is not guaranteed to
  // be 1.
  virtual BigIntVar RandomExactBits(size_t bit_size) const = 0;

  // Generate an exact bit_size random number with the highest bit being 1.
  virtual BigIntVar RandomMonicExactBits(size_t bit_size) const = 0;

  // Generate a random prime number of "bit_size" size
  virtual BigIntVar RandPrimeOver(
      size_t bit_size, PrimeType prime_type = PrimeType::BBS) const = 0;

  virtual std::unique_ptr<MontgomerySpace> CreateMontgomerySpace(
      const BigIntVar& mod) const = 0;
};

}  // namespace yacl::math
