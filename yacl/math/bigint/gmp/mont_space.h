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

namespace yacl::math::gmp {

class GmpMontSpace : public MontgomerySpace {
 public:
  explicit GmpMontSpace(const BigIntVar& mod);

  void MapIntoMSpace(BigIntVar& a) const override;

  void MapBackToZSpace(BigIntVar& a) const override;

  BigIntVar MulMod(const BigIntVar& a, const BigIntVar& b) const override;

  size_t GetWordBitSize() const override { return GMP_NUMB_BITS; }

 private:
  BigIntVar Identity() const override { return r_; }
  Words GetWords(const BigIntVar& e) const override;
  GMPInt n_;       // The modulus N
  mp_limb_t rho_;  // -1/n0 mod b
  GMPInt r_;       // R mod N
  GMPInt rr_;      // R^2 mod N (used to convert to Montgomery form)
};

}  // namespace yacl::math::gmp
