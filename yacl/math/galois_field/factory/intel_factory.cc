// Copyright 2023 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "yacl/math/galois_field/factory/intel_factory.h"

#include <array>
#include <utility>

#include "yacl/base/block.h"

namespace yacl::math {

// Irreducible Polynomials of degree 128 and 64.
constexpr uint64_t kGf128Mod = (1 << 7) | (1 << 2) | (1 << 1) | 1;
constexpr uint64_t kGf64Mod = (1 << 4) | (1 << 3) | (1 << 1) | 1;

namespace {

// carry-less multiplication over Z_{2^128}
// ref:
// https://www.intel.com/content/dam/develop/external/us/en/documents/clmul-wp-rev-2-02-2014-04-20.pdf
// Figure 5 or Algorithm 1
inline std::pair<block, block> cl_mul_128(block x, block y) {
  block low = _mm_clmulepi64_si128(x, y, 0x00);   // low 64 of x, low 64 of y
  block high = _mm_clmulepi64_si128(x, y, 0x11);  // low 64 of x, low 64 of y

  block mid1 = _mm_clmulepi64_si128(x, y, 0x10);  // low 64 of x, high 64 of y
  block mid2 = _mm_clmulepi64_si128(x, y, 0x01);  // high 64 of x, low 64 of y
  block mid = _mm_xor_si128(mid1, mid2);

  mid1 = _mm_srli_si128(mid, 8);  // mid1 = mid >> 64
  mid2 = _mm_slli_si128(mid, 8);  // mid2 =  mid << 64

  high = _mm_xor_si128(high, mid1);  // high ^ (mid >> 64)
  low = _mm_xor_si128(low, mid2);    // low ^ (mid << 64)

  return std::make_pair(high, low);
}

inline block reduce_128(block high, block low) {
  const block modulo = block(kGf128Mod);

  auto [upper, carry0] = cl_mul_128(high, modulo);
  low = _mm_xor_si128(low, carry0);

  auto [zero, carry1] = cl_mul_128(upper, modulo);
  low = _mm_xor_si128(low, carry1);
  return low;
}

// multiplication over Galois Field F_{2^128}
inline block gf_mul_128(block x, block y) {
  auto [high, low] = cl_mul_128(x, y);
  return reduce_128(high, low);
}

// carry-less multiplication over Z_{2^64}
// ref:
// https://github.com/scipr-lab/libff/blob/9769030a06b7ab933d6c064db120019decd359f1/libff/algebra/fields/binary/gf64.cpp#L62
inline uint128_t cl_mul_64(uint64_t x, uint64_t y) {
  block rb = _mm_clmulepi64_si128(_mm_loadl_epi64((const __m128i*)&(x)),
                                  _mm_loadl_epi64((const __m128i*)&(y)), 0x00);
  return toU128(rb);
}

inline uint64_t reduce_64(uint128_t x) {
  const block modulo = block(0, kGf64Mod);
  auto xb = block(x);

  // low 64 of modulo, high 64 of x
  // output is 96 bits, since modulo < 2^32
  auto temp = _mm_clmulepi64_si128(modulo, xb, 0x10);
  xb = _mm_xor_si128(xb, temp);

  // low 64 of modulo, high 64 of temp
  // output is 64 bits, since modulo < 2^32 && high 64 of temp < 2^32
  temp = _mm_clmulepi64_si128(modulo, temp, 0x10);
  xb = _mm_xor_si128(xb, temp);
  return xb.as<uint64_t>()[0];  // low 64 bit
}

}  // namespace

// -----------------------
// Implementaion of SPI
// -----------------------
template <>
uint128_t IntrinsicField<uint128_t>::Mul(const uint128_t& x,
                                         const uint128_t& y) const {
  return toU128(gf_mul_128(block(x), block(y)));
}

template <>
uint64_t IntrinsicField<uint64_t>::Mul(const uint64_t& x,
                                       const uint64_t& y) const {
  return reduce_64(cl_mul_64(x, y));
}

template <>
uint64_t IntrinsicField<uint64_t>::Pow(const uint64_t& x,
                                       const MPInt& y) const {
  uint64_t res = 1;
  uint64_t x_copy = x;
  for (MPInt i = y; i >= 2_mp; i = i / 2_mp) {
    if (i == 1_mp) {
      res = Mul(res, x_copy);
    }
    x_copy = Mul(x_copy, x_copy);
  }
  return res;
}

template <>
uint128_t IntrinsicField<uint128_t>::Pow(
    [[maybe_unused]] const uint128_t& x,
    [[maybe_unused]] const MPInt& y) const {
  YACL_THROW("Not implemented!");
  // uint128_t res = 1;
  // uint128_t x_copy = x;
  // for (MPInt i = y; i >= 2_mp; i = i / 2_mp) {
  //   if (i == 1_mp) {
  //     res = Mul(res, x_copy);
  //   }
  //   x_copy = Mul(x_copy, x_copy);
  // }
  // return res;
}

// Computes z^{2^64-2}
// (by Fermat's little theorem, this is the correct inverse)
template <>
uint64_t IntrinsicField<uint64_t>::Inv(const uint64_t& x) const {
  YACL_ENFORCE(x != 0);
  uint64_t t0 = x;            // x
  uint64_t t1 = Mul(t0, t0);  // x^2
  uint64_t t2 = Mul(t1, t0);  // x^3
  t0 = Mul(t2, t2);           // x^6
  t0 = Mul(t0, t0);           // x^12
  t1 = Mul(t1, t0);           // x^14
  t2 = Mul(t2, t0);           // x^15
  t0 = Mul(t2, t2);           // x^30
  t0 = Mul(t0, t0);           // x^60
  t0 = Mul(t0, t0);           // x^120
  t0 = Mul(t0, t0);           // x^240
  t1 = Mul(t1, t0);           // x^254
  t2 = Mul(t2, t0);
  t0 = Mul(t2, t2);
  t0 = Mul(t0, t0);
  t0 = Mul(t0, t0);
  t0 = Mul(t0, t0);
  t0 = Mul(t0, t0);
  t0 = Mul(t0, t0);
  t0 = Mul(t0, t0);
  t0 = Mul(t0, t0);
  t1 = Mul(t1, t0);
  t2 = Mul(t2, t0);
  t0 = Mul(t2, t2);
  t0 = Mul(t0, t0);
  t0 = Mul(t0, t0);
  t0 = Mul(t0, t0);
  t0 = Mul(t0, t0);
  t0 = Mul(t0, t0);
  t0 = Mul(t0, t0);
  t0 = Mul(t0, t0);
  t0 = Mul(t0, t0);
  t0 = Mul(t0, t0);
  t0 = Mul(t0, t0);
  t0 = Mul(t0, t0);
  t0 = Mul(t0, t0);
  t0 = Mul(t0, t0);
  t0 = Mul(t0, t0);
  t0 = Mul(t0, t0);
  t1 = Mul(t1, t0);
  t0 = Mul(t0, t2);
  for (int i = 0; i < 32; i++) {
    t0 = Mul(t0, t0);
  }
  t0 = Mul(t0, t1);
  return t0;
}

// Computes z^{2^128-2}
// (by Fermat's little theorem, this is the correct inverse)
template <>
uint128_t IntrinsicField<uint128_t>::Inv(const uint128_t& x) const {
  YACL_ENFORCE(x != 0);
  return Pow(x, GetOrder() - 2_mp);
}

// -----------------------
// Register Intrinsic Lib
// -----------------------
REGISTER_GF_LIBRARY(kIntelLib, 100, IntrinsicFieldFactory::Check,
                    IntrinsicFieldFactory::Create);

std::unique_ptr<GaloisField> IntrinsicFieldFactory::Create(
    const std::string& field_name, const SpiArgs& args) {
  YACL_ENFORCE(field_name == kBinaryField);
  auto degree = args.GetRequired(ArgDegree);
  switch (degree) {
    case 64:
      return std::make_unique<IntrinsicField<uint64_t>>();
    case 128:
      return std::make_unique<IntrinsicField<uint128_t>>();
    default:
      YACL_THROW(
          "IntrinsicFieldFactory create failure (for F_2k), unsupported "
          "degree(k) = {}",
          degree);
  }
}

bool IntrinsicFieldFactory::Check(const std::string& field_name,
                                  const SpiArgs& args) {
  return field_name == kBinaryField;
  auto degree = args.GetRequired(ArgDegree);
  if (degree == 64 || degree == 128) {
    return true;
  } else {
    return false;
  }
}

};  // namespace yacl::math
