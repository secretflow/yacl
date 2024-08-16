// Copyright 2023 Ant Group Co., Ltd.
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

#include "yacl/math/galois_field/gf_intrinsic.h"

namespace yacl::math {

// ----------------------------------
// GF 128
// ----------------------------------

void Gf128Mul(uint128_t x, uint128_t y, uint128_t* out) {
  block temp;
  Gf128Mul(block(x), block(y), &temp);
  *out = toU128(temp);
}

void Gf128Mul(block x, block y, block* out) {
  block high;
  block low;
  Gf128ClMul(x, y, &high, &low);
  Gf128Reduce(high, low, out);
}

void Gf128Mul(absl::Span<const uint128_t> x, absl::Span<const uint128_t> y,
              uint128_t* out) {
  YACL_ENFORCE(x.size() == y.size());
  uint128_t high;
  uint128_t low;
  Gf128ClMul(x, y, &high, &low);
  Gf128Reduce(high, low, out);
}

void Gf128ClMul(uint128_t x, uint128_t y, uint128_t* out1, uint128_t* out2) {
  block high;
  block low;
  Gf128ClMul(block(x), block(y), &high, &low);
  *out1 = toU128(high);
  *out2 = toU128(low);
}

void Gf128ClMul(block x, block y, block* out1, block* out2) {
  block low = _mm_clmulepi64_si128(x, y, 0x00);   // low 64 of x, low 64 of y
  block high = _mm_clmulepi64_si128(x, y, 0x11);  // low 64 of x, low 64 of y

  block mid1 = _mm_clmulepi64_si128(x, y, 0x10);  // low 64 of x, high 64 of y
  block mid2 = _mm_clmulepi64_si128(x, y, 0x01);  // high 64 of x, low 64 of y
  block mid = _mm_xor_si128(mid1, mid2);

  mid1 = _mm_srli_si128(mid, 8);  // mid1 = mid >> 64
  mid2 = _mm_slli_si128(mid, 8);  // mid2 =  mid << 64

  *out1 = _mm_xor_si128(high, mid1);  // high ^ (mid >> 64)
  *out2 = _mm_xor_si128(low, mid2);   // low ^ (mid << 64)
}

void Gf128ClMul(absl::Span<const uint128_t> x, absl::Span<const uint128_t> y,
                uint128_t* out1, uint128_t* out2) {
  YACL_ENFORCE(x.size() == y.size());

  const uint64_t size = x.size();
  block ret_high = 0;
  block ret_low = 0;

  for (uint64_t i = 0; i < size; ++i) {
    block high;
    block low;
    Gf128ClMul(block(x[i]), block(y[i]), &high, &low);
    ret_high = _mm_xor_si128(ret_high, high);
    ret_low = _mm_xor_si128(ret_low, low);
  }
  *out1 = toU128(ret_high);
  *out2 = toU128(ret_low);
}

void Gf128Reduce(block high, block low, block* out) {
  const block modulo = block(kGfMod128);
  block upper;
  block carry0;
  block carry1;
  block zero;
  Gf128ClMul(high, modulo, &upper, &carry0);
  low = _mm_xor_si128(low, carry0);
  Gf128ClMul(upper, modulo, &zero, &carry1);
  *out = _mm_xor_si128(low, carry1);
}

void Gf128Reduce(uint128_t high, uint128_t low, uint128_t* out) {
  block temp;
  Gf128Reduce(block(high), block(low), &temp);
  *out = toU128(temp);
}

void Gf128Pack(absl::Span<const uint128_t> data, uint128_t* out) {
  const size_t size = data.size();
  YACL_ENFORCE(size <= 128);
  Gf128Mul(data, absl::MakeSpan(kGf128Basis().data(), size), out);
}

// ----------------------------------
// GF 64
// ----------------------------------

void Gf64Mul(uint64_t x, uint64_t y, uint64_t* out) {
  uint128_t temp;
  Gf64ClMul(x, y, &temp);
  Gf64Reduce(temp, out);
}

void Gf64Mul(absl::Span<const uint64_t> x, absl::Span<const uint64_t> y,
             uint64_t* out) {
  YACL_ENFORCE(x.size() == y.size());
  uint128_t temp;
  Gf64ClMul(x, y, &temp);
  Gf64Reduce(temp, out);
}

void Gf64ClMul(uint64_t x, uint64_t y, uint128_t* out) {
  *out =
      toU128(_mm_clmulepi64_si128(_mm_loadl_epi64((const __m128i*)&(x)),
                                  _mm_loadl_epi64((const __m128i*)&(y)), 0x00));
}

void Gf64ClMul(absl::Span<const uint64_t> x, absl::Span<const uint64_t> y,
               uint128_t* out) {
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
    uint128_t temp;
    Gf64ClMul(x[i], y[i], &temp);
    ret = _mm_xor_si128(ret, block(temp));
  }

  *out = toU128(ret);
}

void Gf64Reduce(uint128_t x, uint64_t* out) {
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
  *out = xb.as<uint64_t>()[0];  // low 64 bit
}

void Gf64Inv(uint64_t x, uint64_t* out) {
  uint64_t t0 = x;
  uint64_t t1;
  uint64_t t2;
  Gf64Mul(t0, t0, &t1);
  Gf64Mul(t1, t0, &t2);
  Gf64Mul(t2, t2, &t0);
  Gf64Mul(t0, t0, &t0);
  Gf64Mul(t1, t0, &t1);
  Gf64Mul(t2, t0, &t2);
  Gf64Mul(t2, t2, &t0);
  Gf64Mul(t0, t0, &t0);
  Gf64Mul(t0, t0, &t0);
  Gf64Mul(t0, t0, &t0);
  Gf64Mul(t1, t0, &t1);
  Gf64Mul(t2, t0, &t2);
  Gf64Mul(t2, t2, &t0);
  Gf64Mul(t0, t0, &t0);
  Gf64Mul(t0, t0, &t0);
  Gf64Mul(t0, t0, &t0);
  Gf64Mul(t0, t0, &t0);
  Gf64Mul(t0, t0, &t0);
  Gf64Mul(t0, t0, &t0);
  Gf64Mul(t0, t0, &t0);
  Gf64Mul(t1, t0, &t1);
  Gf64Mul(t2, t0, &t2);
  Gf64Mul(t2, t2, &t0);
  Gf64Mul(t0, t0, &t0);
  Gf64Mul(t0, t0, &t0);
  Gf64Mul(t0, t0, &t0);
  Gf64Mul(t0, t0, &t0);
  Gf64Mul(t0, t0, &t0);
  Gf64Mul(t0, t0, &t0);
  Gf64Mul(t0, t0, &t0);
  Gf64Mul(t0, t0, &t0);
  Gf64Mul(t0, t0, &t0);
  Gf64Mul(t0, t0, &t0);
  Gf64Mul(t0, t0, &t0);
  Gf64Mul(t0, t0, &t0);
  Gf64Mul(t0, t0, &t0);
  Gf64Mul(t0, t0, &t0);
  Gf64Mul(t0, t0, &t0);
  Gf64Mul(t1, t0, &t1);
  Gf64Mul(t0, t2, &t0);
  for (int i = 0; i < 32; i++) {
    Gf64Mul(t0, t0, &t0);
  }
  Gf64Mul(t0, t1, out);
}

// ------------------------
// GF Function Alias
// ------------------------

uint64_t Gf64Mul(uint64_t x, uint64_t y) {
  uint64_t ret;
  Gf64Mul(x, y, &ret);
  return ret;
}

uint64_t Gf64Mul(absl::Span<const uint64_t> x, absl::Span<const uint64_t> y) {
  uint64_t ret;
  Gf64Mul(x, y, &ret);
  return ret;
}

uint64_t Gf64Pack(absl::Span<const uint64_t> data) {
  uint64_t ret;
  Gf64Pack(data, &ret);
  return ret;
}
void Gf64Pack(absl::Span<const uint64_t> data, uint64_t* out) {
  const size_t size = data.size();
  YACL_ENFORCE(size <= 64);
  Gf64Mul(data, absl::MakeSpan(kGf64Basis().data(), size), out);
}

uint64_t Gf64Inv(uint64_t x) {
  uint64_t ret;
  Gf64Inv(x, &ret);
  return ret;
}

uint64_t Gf64Reduce(uint128_t x) {
  uint64_t ret;
  Gf64Reduce(x, &ret);
  return ret;
}

uint128_t Gf64ClMul(uint64_t x, uint64_t y) {
  uint128_t ret;
  Gf64ClMul(x, y, &ret);
  return ret;
}

uint128_t Gf64ClMul(absl::Span<const uint64_t> x,
                    absl::Span<const uint64_t> y) {
  uint128_t ret;
  Gf64ClMul(x, y, &ret);
  return ret;
}

uint128_t Gf128Mul(uint128_t x, uint128_t y) {
  uint128_t ret;
  Gf128Mul(x, y, &ret);
  return ret;
}

block Gf128Mul(block x, block y) {
  block ret;
  Gf128Mul(x, y, &ret);
  return ret;
}

uint128_t Gf128Reduce(uint128_t high, uint128_t low) {
  uint128_t ret;
  Gf128Reduce(high, low, &ret);
  return ret;
}

block Gf128Reduce(block high, block low) {
  block ret;
  Gf128Reduce(high, low, &ret);
  return ret;
}

uint128_t Gf128Mul(absl::Span<const uint128_t> x,
                   absl::Span<const uint128_t> y) {
  uint128_t ret;
  Gf128Mul(x, y, &ret);
  return ret;
}

uint128_t Gf128Pack(absl::Span<const uint128_t> data) {
  uint128_t ret;
  Gf128Pack(data, &ret);
  return ret;
}

uint128_t GfMul(absl::Span<const uint128_t> a, absl::Span<const uint64_t> b) {
  UninitAlignedVector<uint128_t> tmp(b.size());
  std::transform(b.cbegin(), b.cend(), tmp.begin(), [](const uint64_t& val) {
    return static_cast<uint128_t>(val);
  });
  return Gf128Mul(a, absl::MakeSpan(tmp));
}

uint128_t GfMul(absl::Span<const uint64_t> a, absl::Span<const uint128_t> b) {
  return GfMul(b, a);
}

}  // namespace yacl::math
