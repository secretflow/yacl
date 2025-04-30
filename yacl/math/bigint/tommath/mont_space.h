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

namespace yacl::math::tommath {

class MPIntMontSpace : public MontgomerySpace {
 public:
  explicit MPIntMontSpace(const BigIntVar& mod);

  void MapIntoMSpace(BigIntVar& a) const override;

  void MapBackToZSpace(BigIntVar& a) const override;

  BigIntVar MulMod(const BigIntVar& a, const BigIntVar& b) const override;

  size_t GetWordBitSize() const override { return MP_DIGIT_BIT; }

 private:
  BigIntVar Identity() const override { return identity_; }
  Words GetWords(const BigIntVar& e) const override;
  MPInt mod_;       // The original modulus (m)
  mp_digit mp_;     // mp = -m^-1 mod R
  MPInt identity_;  // identity = R mod m // i.e. unit 1 in Montgomery ring
};

}  // namespace yacl::math::tommath
