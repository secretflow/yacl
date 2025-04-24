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

#include "yacl/math/bigint/gmp/gmp_lib.h"

#include "yacl/math/bigint/gmp/mont_space.h"

namespace yacl::math::gmp {

BigIntVar GmpLib::NewBigInt() const { return GMPInt(); }

BigIntVar GmpLib::NewBigInt(size_t reserved_bits) const {
  return GMPInt(0, reserved_bits);
}

BigIntVar GmpLib::NewBigInt(const std::string& str, int base) const {
  return GMPInt(str, base);
}

BigIntVar GmpLib::RandomExactBits(size_t bit_size) const {
  return GMPInt::RandomExactBits(bit_size);
}

BigIntVar GmpLib::RandomMonicExactBits(size_t bit_size) const {
  return GMPInt::RandomMonicExactBits(bit_size);
}

BigIntVar GmpLib::RandPrimeOver(size_t bit_size, PrimeType prime_type) const {
  return GMPInt::RandPrimeOver(bit_size, prime_type);
}

std::unique_ptr<MontgomerySpace> GmpLib::CreateMontgomerySpace(
    const BigIntVar& mod) const {
  return std::make_unique<GmpMontSpace>(mod);
}

}  // namespace yacl::math::gmp
