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

#pragma once

#include <array>
#include <cstdint>
#include <iostream>
#include <limits>
#include <utility>

#include "yacl/base/aligned_vector.h"
#include "yacl/base/block.h"
#include "yacl/base/exception.h"
#include "yacl/base/int128.h"
#include "yacl/math/gadget.h"

namespace yacl::math {

// Galois Field GF(2^n) implmentation
// (As of now, only support GF(2^64) & GF(2^128))
//
// Galois Field GF(2^n) could be viewed as GF(2)[X]/(P),
// where P is an irreducible polynomial in GF(2)[X] of degree n.
//
// NOTE To achieve multiplication over GF(2^n):
// 1. Perform polynomial multiplication over GF(2)[X], as known as, carry-less
// multiplication.
// 2. Reduce the product modulo the irreducible polynomial.

// Irreducible Polynomials of degree 128 and 64.
constexpr uint64_t kGfMod128 = (1 << 7) | (1 << 2) | (1 << 1) | 1;
constexpr uint64_t kGfMod64 = (1 << 4) | (1 << 3) | (1 << 1) | 1;

constexpr auto kGf64Basis = []() constexpr {
  std::array<uint64_t, 64> basis = {0};
  uint128_t one = yacl::MakeUint128(0, 1);
  for (size_t i = 0; i < 64; ++i) {
    basis[i] = one << i;
  }
  return basis;
};

constexpr auto kGf128Basis = []() constexpr {
  std::array<uint128_t, 128> basis = {0};
  uint128_t one = yacl::MakeUint128(0, 1);
  for (size_t i = 0; i < 128; ++i) {
    basis[i] = one << i;
  }
  return basis;
};

// ----------------------------------
// GF 128
// ----------------------------------
void Gf128Mul(uint128_t x, uint128_t y, uint128_t* out);
uint128_t Gf128Mul(uint128_t x, uint128_t y);

void Gf128Mul(block x, block y, block* out);
block Gf128Mul(block x, block y);

void Gf128Mul(absl::Span<const uint128_t> x, absl::Span<const uint128_t> y,
              uint128_t* out);
uint128_t Gf128Mul(absl::Span<const uint128_t> x,
                   absl::Span<const uint128_t> y);

void Gf128ClMul(uint128_t x, uint128_t y, uint128_t* out1, uint128_t* out2);
void Gf128ClMul(block x, block y, block* out1, block* out2);
void Gf128ClMul(absl::Span<const uint128_t> x, absl::Span<const uint128_t> y,
                uint128_t* out1, uint128_t* out2);

void Gf128Reduce(uint128_t high, uint128_t low, uint128_t* out);
uint128_t Gf128Reduce(uint128_t high, uint128_t low);

void Gf128Reduce(block high, block low, block* out);
block Gf128Reduce(block high, block low);

void Gf128Pack(absl::Span<const uint128_t> data, uint128_t* out);
uint128_t Gf128Pack(absl::Span<const uint128_t> data);

// ----------------------------------
// GF 64
// ----------------------------------
void Gf64Mul(uint64_t x, uint64_t y, uint64_t* out);
uint64_t Gf64Mul(uint64_t x, uint64_t y);

void Gf64Mul(absl::Span<const uint64_t> x, absl::Span<const uint64_t> y,
             uint64_t* out);
uint64_t Gf64Mul(absl::Span<const uint64_t> x, absl::Span<const uint64_t> y);

void Gf64ClMul(uint64_t x, uint64_t y, uint128_t* out);
uint128_t Gf64ClMul(uint64_t x, uint64_t y);

void Gf64ClMul(absl::Span<const uint64_t> x, absl::Span<const uint64_t> y,
               uint128_t* out);
uint128_t Gf64ClMul(absl::Span<const uint64_t> x, absl::Span<const uint64_t> y);

void Gf64Reduce(uint128_t x, uint64_t* out);
uint64_t Gf64Reduce(uint128_t x);

void Gf64Inv(uint64_t x, uint64_t* out);
uint64_t Gf64Inv(uint64_t x);

void Gf64Pack(absl::Span<const uint64_t> data, uint64_t* out);
uint64_t Gf64Pack(absl::Span<const uint64_t> data);

// ------------------------
// Generic Multiplication
// ------------------------

inline uint128_t GfMul(uint128_t x, uint128_t y) { return Gf128Mul(x, y); }
inline uint128_t GfMul(absl::Span<const uint128_t> a,
                       absl::Span<const uint128_t> b) {
  return Gf128Mul(a, b);
}

inline uint64_t GfMul(uint64_t x, uint64_t y) { return Gf64Mul(x, y); }
inline uint64_t GfMul(absl::Span<const uint64_t> a,
                      absl::Span<const uint64_t> b) {
  return Gf64Mul(a, b);
}

// NOTE The subfield (a.k.a GF(2^64)) is mapped to the larger field (a.k.a
// GF(2^128)) to proceed with arithmatic operations. Therefore, all subfield ops
// such as multiplications and additions are defined in GF(2^128)
//
uint128_t GfMul(absl::Span<const uint128_t> a, absl::Span<const uint64_t> b);
uint128_t GfMul(absl::Span<const uint64_t> a, absl::Span<const uint128_t> b);
inline uint128_t GfMul(uint128_t a, uint64_t b) {
  return Gf128Mul(a, MakeUint128(0, b));
}

inline uint128_t GfMul(uint64_t a, uint128_t b) {
  return Gf128Mul(MakeUint128(0, a), b);
}

// ------------------------
// GF Universal Hash
// ------------------------

// see difference between universal hash and collision-resistent hash functions:
// https://crypto.stackexchange.com/a/88247/61581
template <typename T>
T UniversalHash(T seed, absl::Span<const T> data) {
  T ret = 0;
  for_each(data.rbegin(), data.rend(), [&ret, &seed](const T& val) {
    ret ^= val;
    ret = GfMul(seed, ret);
  });
  return ret;
}

template <typename T>
std::vector<T> ExtractHashCoef(T seed,
                               absl::Span<const uint64_t> indexes /*sorted*/) {
  std::array<T, 64> buff = {};
  auto max_bits = math::Log2Ceil(indexes.back());
  buff[0] = seed;
  for (size_t i = 1; i <= max_bits; ++i) {
    buff[i] = GfMul(buff[i - 1], buff[i - 1]);
  }

  std::vector<T> ret;
  for (const auto& index : indexes) {
    auto index_plus_one = index + 1;
    uint64_t mask = 1;
    T coef = 1;
    for (size_t i = 0; i < 64 && mask <= index_plus_one; ++i) {
      if (mask & index_plus_one) {
        coef = GfMul(coef, buff[i]);
      }
      mask <<= 1;
    }
    ret.push_back(coef);
  }
  return ret;
}

}  // namespace yacl::math
