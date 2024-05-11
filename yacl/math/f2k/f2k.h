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

#pragma once

#include <array>
#include <cstdint>
#include <iostream>
#include <limits>
#include <utility>

#include "yacl/base/block.h"
#include "yacl/base/exception.h"
#include "yacl/base/int128.h"

// Galois Field GF(2^n) implmentation
// (As of now, only support GF(2^64) & GF(2^128))
//
// Galois Field GF(2^n) could be viewed as GF(2)[X]/(P),
// where P is an irreducible polynomial in GF(2)[X] of degree n.
//
// To achieve multiplication over GF(2^n):
// 1. Perform polynomial multiplication over GF(2)[X], as known as, carry-less
// multiplication.
// 2. Reduce the product modulo the irreducible polynomial.
//
// For example, in GF(2^8) = GF(2)[X]/(x^8+x^4+x^3+x^2+x+1)
//
// x^7 x^6 x^5 x^4 x^3 x^2 x^1 x^0     x^7 x^6 x^5 x^4 x^3 x^2 x^1 x^0
//  1   0   0   0   0   1   1   1   *   0   0   0   0   0   0   1   0
//                                         (carry-less multiplication)
//   x^8 x^7 x^6 x^5 x^4 x^3 x^2 x^1 x^0
// =  1   0   0   0   0   1   1   1   0
//                                      (reducing by x^8+x^4+x^3+x^2+x+1)
//   x^7 x^6 x^5 x^4 x^3 x^2 x^1 x^0
// =  0   0   0   1   0   1   0   1
//
// For more information,
// 1. properties about GF(2^n)
// https://engineering.purdue.edu/kak/compsec/NewLectures/Lecture7.pdf
// 2. binary irreducible polynomials:
// https://www.hpl.hp.com/techreports/98/HPL-98-135.pdf

namespace yacl {

// Irreducible Polynomials of degree 128 and 64.
constexpr uint64_t kGfMod128 = (1 << 7) | (1 << 2) | (1 << 1) | 1;
constexpr uint64_t kGfMod64 = (1 << 4) | (1 << 3) | (1 << 1) | 1;

// carry-less multiplication over Z_{2^128}
// ref:
// https://www.intel.com/content/dam/develop/external/us/en/documents/clmul-wp-rev-2-02-2014-04-20.pdf
// Figure 5 or Algorithm 1
inline std::pair<block, block> ClMul128(block x, block y) {
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

inline std::pair<uint128_t, uint128_t> ClMul128(uint128_t x, uint128_t y) {
  auto [high, low] = ClMul128(block(x), block(y));
  return std::make_pair(toU128(high), toU128(low));
}

inline block Reduce128(block high, block low) {
  const block modulo = block(kGfMod128);

  auto [upper, carry0] = ClMul128(high, modulo);
  low = _mm_xor_si128(low, carry0);

  auto [zero, carry1] = ClMul128(upper, modulo);
  low = _mm_xor_si128(low, carry1);
  return low;
}

inline uint128_t Reduce128(uint128_t high, uint128_t low) {
  return toU128(Reduce128(block(high), block(low)));
}

// multiplication over Galois Field F_{2^128}
inline block GfMul128(block x, block y) {
  auto [high, low] = ClMul128(x, y);
  return Reduce128(high, low);
}

inline uint128_t GfMul128(uint128_t x, uint128_t y) {
  return toU128(GfMul128(block(x), block(y)));
}

// carry-less multiplication over Z_{2^64}
// ref:
// https://github.com/scipr-lab/libff/blob/9769030a06b7ab933d6c064db120019decd359f1/libff/algebra/fields/binary/gf64.cpp#L62
inline uint128_t ClMul64(uint64_t x, uint64_t y) {
  block rb = _mm_clmulepi64_si128(_mm_loadl_epi64((const __m128i*)&(x)),
                                  _mm_loadl_epi64((const __m128i*)&(y)), 0x00);
  return toU128(rb);
}

inline uint64_t Reduce64(uint128_t x) {
  const block modulo = block(0, kGfMod64);
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

// multiplication over Galois Field F_{2^64}
inline uint64_t GfMul64(uint64_t x, uint64_t y) {
  return Reduce64(ClMul64(x, y));
}

// inverse over Galois Field F_{2^64}
inline uint64_t GfInv64(uint64_t x) {
  uint64_t t0 = x;
  uint64_t t1 = GfMul64(t0, t0);
  uint64_t t2 = GfMul64(t1, t0);
  t0 = GfMul64(t2, t2);
  t0 = GfMul64(t0, t0);
  t1 = GfMul64(t1, t0);
  t2 = GfMul64(t2, t0);
  t0 = GfMul64(t2, t2);
  t0 = GfMul64(t0, t0);
  t0 = GfMul64(t0, t0);
  t0 = GfMul64(t0, t0);
  t1 = GfMul64(t1, t0);
  t2 = GfMul64(t2, t0);
  t0 = GfMul64(t2, t2);
  t0 = GfMul64(t0, t0);
  t0 = GfMul64(t0, t0);
  t0 = GfMul64(t0, t0);
  t0 = GfMul64(t0, t0);
  t0 = GfMul64(t0, t0);
  t0 = GfMul64(t0, t0);
  t0 = GfMul64(t0, t0);
  t1 = GfMul64(t1, t0);
  t2 = GfMul64(t2, t0);
  t0 = GfMul64(t2, t2);
  t0 = GfMul64(t0, t0);
  t0 = GfMul64(t0, t0);
  t0 = GfMul64(t0, t0);
  t0 = GfMul64(t0, t0);
  t0 = GfMul64(t0, t0);
  t0 = GfMul64(t0, t0);
  t0 = GfMul64(t0, t0);
  t0 = GfMul64(t0, t0);
  t0 = GfMul64(t0, t0);
  t0 = GfMul64(t0, t0);
  t0 = GfMul64(t0, t0);
  t0 = GfMul64(t0, t0);
  t0 = GfMul64(t0, t0);
  t0 = GfMul64(t0, t0);
  t0 = GfMul64(t0, t0);
  t1 = GfMul64(t1, t0);
  t0 = GfMul64(t0, t2);
  for (int i = 0; i < 32; i++) {
    t0 = GfMul64(t0, t0);
  }
  t0 = GfMul64(t0, t1);
  return t0;
}

// Inner product <x,y>
inline std::pair<uint128_t, uint128_t> ClMul128(absl::Span<const uint128_t> x,
                                                absl::Span<const uint128_t> y) {
  YACL_ENFORCE(x.size() == y.size());

  const uint64_t size = x.size();
  block ret_high = 0;
  block ret_low = 0;

  for (uint64_t i = 0; i < size; ++i) {
    auto [high, low] = ClMul128(block(x[i]), block(y[i]));
    ret_high = _mm_xor_si128(ret_high, high);
    ret_low = _mm_xor_si128(ret_low, low);
  }
  return std::make_pair(toU128(ret_high), toU128(ret_low));
}

inline uint128_t GfMul128(absl::Span<const uint128_t> x,
                          absl::Span<const uint128_t> y) {
  YACL_ENFORCE(x.size() == y.size());
  auto [high, low] = ClMul128(x, y);
  return Reduce128(high, low);
}

inline uint128_t ClMul64(absl::Span<const uint64_t> x,
                         absl::Span<const uint64_t> y) {
  YACL_ENFORCE(x.size() == y.size());

  const uint64_t size = x.size();
  block ret = 0;

  uint64_t i = 0;
  for (; i + 1 < size; i += 2) {
    // pack
    block xb = block(x[i + 1], x[i]);
    block yb = block(y[i + 1], y[i]);
    // low 64 of xb, low 64 of yb, x[i] * y[i]
    block xy0 = _mm_clmulepi64_si128(xb, yb, 0x00);
    // high 64 of xb, high 64 of yb, x[i+1] * y[i+1]
    block xy1 = _mm_clmulepi64_si128(xb, yb, 0x11);
    // xor
    ret = _mm_xor_si128(ret, xy0);
    ret = _mm_xor_si128(ret, xy1);
  }

  for (; i < size; ++i) {
    auto temp = block(ClMul64(x[i], y[i]));
    ret = _mm_xor_si128(ret, temp);
  }

  return toU128(ret);
}

inline uint64_t GfMul64(absl::Span<const uint64_t> x,
                        absl::Span<const uint64_t> y) {
  YACL_ENFORCE(x.size() == y.size());
  return Reduce64(ClMul64(x, y));
}

// As of now, f2k only support GF(2^128) and GF(2^64)
// TODO: @wenfan implement GF(2^k)
// // Reduce Z_{2^128} to Galois Field F_{2^k}
// uint64_t Reduce(uint128_t x,uint64_t k);
// // multiplication over Galois Field F_{2^k}
// uint64_t GfMul(uint64_t x, uint64_t y, uint64_t k);

inline std::array<uint128_t, 128> GenGf128Basis() {
  std::array<uint128_t, 128> basis = {0};
  uint128_t one = yacl::MakeUint128(0, 1);
  for (size_t i = 0; i < 128; ++i) {
    basis[i] = one << i;
  }
  return basis;
}

inline std::array<uint64_t, 64> GenGf64Basis() {
  std::array<uint64_t, 64> basis = {0};
  uint128_t one = yacl::MakeUint128(0, 1);
  for (size_t i = 0; i < 64; ++i) {
    basis[i] = one << i;
  }
  return basis;
}

static std::array<uint64_t, 64> gf64_basis = GenGf64Basis();
static std::array<uint128_t, 128> gf128_basis = GenGf128Basis();

inline uint128_t PackGf128(absl::Span<const uint128_t> data) {
  const size_t size = data.size();
  YACL_ENFORCE(size <= 128);
  // inner product
  return GfMul128(data, absl::MakeSpan(gf128_basis.data(), size));
}

inline uint64_t PackGf64(absl::Span<const uint64_t> data) {
  const size_t size = data.size();
  YACL_ENFORCE(size <= 64);
  // inner product
  return GfMul64(data, absl::MakeSpan(gf64_basis.data(), size));
}
};  // namespace yacl
