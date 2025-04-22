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

#include "yacl/math/bigint/tommath/tommath_lib.h"

#include "yacl/math/bigint/tommath/mont_space.h"

namespace yacl::math::tommath {

BigIntVar TomMathLib::NewBigInt() const { return MPInt(); }

BigIntVar TomMathLib::NewBigInt(size_t reserved_bits) const {
  return MPInt(0, reserved_bits);
}

BigIntVar TomMathLib::NewBigInt(const std::string& str, int base) const {
  return MPInt(str, base);
}

BigIntVar TomMathLib::RandomExactBits(size_t bit_size) const {
  MPInt r(0, bit_size);
  MPInt::RandomExactBits(bit_size, &r);
  return r;
}

BigIntVar TomMathLib::RandomMonicExactBits(size_t bit_size) const {
  MPInt r(0, bit_size);
  MPInt::RandomMonicExactBits(bit_size, &r);
  return r;
}

BigIntVar TomMathLib::RandPrimeOver(size_t bit_size,
                                    PrimeType prime_type) const {
  MPInt r(0, bit_size);
  MPInt::RandPrimeOver(bit_size, &r, prime_type);
  return r;
}

std::unique_ptr<MontgomerySpace> TomMathLib::CreateMontgomerySpace(
    const BigIntVar& mod) const {
  return std::make_unique<MPIntMontSpace>(mod);
}

}  // namespace yacl::math::tommath
