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

#include "yacl/math/bigint/gmp/mont_space.h"

namespace yacl::math::gmp {

namespace {
inline const GMPInt& CastBigInt(const BigIntVar& n) {
  YACL_ENFORCE(std::holds_alternative<GMPInt>(n),
               "Illegal BigInt, expected GMPInt, real={}", n.index());
  return std::get<GMPInt>(n);
}

inline GMPInt& CastBigInt(BigIntVar& n) {
  YACL_ENFORCE(std::holds_alternative<GMPInt>(n),
               "Illegal BigInt, expected GMPInt, real={}", n.index());
  return std::get<GMPInt>(n);
}
}  // namespace

GmpMontSpace::GmpMontSpace(const BigIntVar& mod) : MontgomerySpace(mod) {
  n_ = CastBigInt(mod);
  rho_ = GMPInt::MontgomerySetup(n_);
  r_ = GMPInt::MontgomeryCalcNormalization(n_);
  rr_ = r_.MulMod(r_, n_);
}

void GmpMontSpace::MapIntoMSpace(BigIntVar& a) const {
  auto& z = CastBigInt(a);
  if (z.IsNegative() || z >= n_) {
    z %= n_;
  }
  z *= rr_;
  z.MontgomeryReduce(n_, rho_);
}

void GmpMontSpace::MapBackToZSpace(BigIntVar& a) const {
  CastBigInt(a).MontgomeryReduce(n_, rho_);
}

BigIntVar GmpMontSpace::MulMod(const BigIntVar& a, const BigIntVar& b) const {
  BigIntVar r = CastBigInt(a) * CastBigInt(b);
  CastBigInt(r).MontgomeryReduce(n_, rho_);
  return r;
}

auto GmpMontSpace::GetWords(const BigIntVar& e) const -> Words {
  Words words;
  words.num_words = GMPLoader::Instance().mpz_size_(CastBigInt(e).z_);
  // Type casting is required when compiling on macOS
  words.data = reinterpret_cast<const uint64_t*>(
      GMPLoader::Instance().mpz_limbs_read_(CastBigInt(e).z_));
  words.need_free = false;
  return words;
}

}  // namespace yacl::math::gmp
