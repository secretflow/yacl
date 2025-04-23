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

#include "yacl/math/bigint/openssl/openssl_lib.h"

#include "yacl/math/bigint/openssl/mont_space.h"

namespace yacl::math::openssl {

BigIntVar OpensslLib::NewBigInt() const { return BigNum(); }

BigIntVar OpensslLib::NewBigInt(size_t) const { return BigNum(); }

BigIntVar OpensslLib::NewBigInt(const std::string& str, int base) const {
  return BigNum(str, base);
}

BigIntVar OpensslLib::RandPrimeOver(size_t bit_size,
                                    PrimeType prime_type) const {
  return BigNum::RandPrimeOver(bit_size, prime_type);
}

BigIntVar OpensslLib::RandomExactBits(size_t bit_size) const {
  return BigNum::RandomExactBits(bit_size);
}

BigIntVar OpensslLib::RandomMonicExactBits(size_t bit_size) const {
  return BigNum::RandomMonicExactBits(bit_size);
}

std::unique_ptr<MontgomerySpace> OpensslLib::CreateMontgomerySpace(
    const BigIntVar& mod) const {
  return std::make_unique<OpensslMontSpace>(mod);
}

}  // namespace yacl::math::openssl
