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

#include "yacl/math/bigint/openssl/mont_space.h"

#include "yacl/utils/spi/type_traits.h"

namespace yacl::math::openssl {

namespace {

inline const BigNum &CastBigInt(const BigIntVar &n) {
  YACL_ENFORCE(std::holds_alternative<BigNum>(n),
               "Illegal BigInt, expected BigNum, real={}", n.index());
  return std::get<BigNum>(n);
}

inline BigNum &CastBigInt(BigIntVar &n) {
  YACL_ENFORCE(std::holds_alternative<BigNum>(n),
               "Illegal BigInt, expected BigNum, real={}", n.index());
  return std::get<BigNum>(n);
}
}  // namespace

OpensslMontSpace::OpensslMontSpace(const BigIntVar &mod)
    : MontgomerySpace(mod) {
  mod_ = CastBigInt(mod);
  bn_mont_ctx_ = BigNum::SetMontgomeryCtx(mod_);
  identity_ = 1;
  identity_.ToMontgomery(bn_mont_ctx_);
}

void OpensslMontSpace::MapIntoMSpace(BigIntVar &a) const {
  auto &z = CastBigInt(a);
  if (z.IsNegative() || z >= mod_) {
    z %= mod_;
  }
  CastBigInt(a).ToMontgomery(bn_mont_ctx_);
}

void OpensslMontSpace::MapBackToZSpace(BigIntVar &a) const {
  CastBigInt(a).FromMontgomery(bn_mont_ctx_);
}

BigIntVar OpensslMontSpace::MulMod(const BigIntVar &a,
                                   const BigIntVar &b) const {
  return BigNum::MulModMontgomery(CastBigInt(a), CastBigInt(b), bn_mont_ctx_);
}

auto OpensslMontSpace::GetWords(const BigIntVar &e) const -> Words {
  Words words;
  int num_bytes = BN_num_bytes(CastBigInt(e).bn_.get());
  words.num_words = (num_bytes + 7) / 8;
  words.data = new uint64_t[words.num_words];
  words.need_free = true;
  BN_bn2lebinpad(CastBigInt(e).bn_.get(), (uint8_t *)words.data,
                 words.num_words * 8);
  if constexpr (yacl::Endian::native == yacl::Endian::big) {
    for (size_t i = 0; i < words.num_words; ++i) {
      *((uint64_t *)(words.data + i)) =
          absl::little_endian::ToHost(words.data[i]);
    }
  }
  return words;
}

}  // namespace yacl::math::openssl
