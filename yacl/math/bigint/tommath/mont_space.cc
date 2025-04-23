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

#include "yacl/math/bigint/tommath/mont_space.h"

namespace yacl::math::tommath {

namespace {
inline const MPInt& CastBigInt(const BigIntVar& n) {
  YACL_ENFORCE(std::holds_alternative<MPInt>(n),
               "Illegal BigInt, expected MPInt, real={}", n.index());
  return std::get<MPInt>(n);
}

inline MPInt& CastBigInt(BigIntVar& n) {
  YACL_ENFORCE(std::holds_alternative<MPInt>(n),
               "Illegal BigInt, expected MPInt, real={}", n.index());
  return std::get<MPInt>(n);
}
}  // namespace

MPIntMontSpace::MPIntMontSpace(const BigIntVar& mod)
    : MontgomerySpace(mod), identity_(0) {
  // init identity_ to 0 to make sure memory is allocated
  mod_ = CastBigInt(mod);
  MPINT_ENFORCE_OK(mp_montgomery_setup(&mod_.n_, &mp_));
  MPINT_ENFORCE_OK(mp_montgomery_calc_normalization(&identity_.n_, &mod_.n_));
}

void MPIntMontSpace::MapIntoMSpace(BigIntVar& a) const {
  MPINT_ENFORCE_OK(
      mp_mulmod(&CastBigInt(a).n_, &identity_.n_, &mod_.n_, &CastBigInt(a).n_));
}

void MPIntMontSpace::MapBackToZSpace(BigIntVar& a) const {
  MPINT_ENFORCE_OK(mp_montgomery_reduce(&CastBigInt(a).n_, &mod_.n_, mp_));
}

BigIntVar MPIntMontSpace::MulMod(const BigIntVar& a, const BigIntVar& b) const {
  MPInt r;
  MPINT_ENFORCE_OK(mp_mul(&CastBigInt(a).n_, &CastBigInt(b).n_, &r.n_));
  MPINT_ENFORCE_OK(mp_montgomery_reduce(&r.n_, &mod_.n_, mp_));
  return r;
}

auto MPIntMontSpace::GetWords(const BigIntVar& e) const -> Words {
  Words words;
  words.num_words = CastBigInt(e).n_.used;
  words.data = CastBigInt(e).n_.dp;
  words.need_free = false;
  return words;
}

}  // namespace yacl::math::tommath
