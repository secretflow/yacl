// Copyright 2026 Ant Group Co., Ltd.
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

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "yacl/base/exception.h"
#include "yacl/base/int128.h"

#ifdef YACL_CRYPTO_EXPERIMENTAL_POLY_ENABLE_OSTREAM
#include <ostream>
#endif

namespace yacl::crypto::experimental::poly {

// 说明：这里用 __int128 来保证 64-bit 模数下的正确性（YACL 仅支持
// GCC/Clang）。
#if !defined(__SIZEOF_INT128__)
#error \
    "prime_field.h requires compiler support for unsigned __int128 (GCC/Clang)."
#endif

using u64 = std::uint64_t;
using u128 = uint128_t;
using i128 = int128_t;

// 素域元素：仅存值 v，约定始终保持 0 <= v < p（规范表示）。
struct Fp {
  u64 v = 0;

  std::string ToString() const { return std::to_string(v); }
};

#ifdef YACL_CRYPTO_EXPERIMENTAL_POLY_ENABLE_OSTREAM
// 仅做调试输出（可选）。
inline std::ostream& operator<<(std::ostream& os, const Fp& x) {
  return os << x.v;
}
#endif

// 素域上下文：只保存模数 p（假设 p 是素数）。
struct FpContext {
  u64 p;
  bool is_mersenne_ = false;
  unsigned mersenne_k_ = 0;  // p = 2^k - 1
  u64 mersenne_mask_ = 0;

  // 不做素性测试；只做最基本合法性检查。
  explicit FpContext(u64 prime_mod) : p(prime_mod) {
    if (p < 2) {
      YACL_THROW_ARGUMENT_ERROR("FpContext: modulus p must be >= 2");
    }

    // Detect p = 2^k - 1 (Mersenne); used for fast reduction paths.
    is_mersenne_ = ((p & (p + 1)) == 0);
    if (is_mersenne_) {
      mersenne_mask_ = p;  // == (1ULL << k) - 1
      mersenne_k_ = 64U - static_cast<unsigned>(absl::countl_zero(p));
      if (mersenne_k_ >= 64U) {  // avoid undefined shift when p == 2^64-1
        is_mersenne_ = false;
        mersenne_k_ = 0;
        mersenne_mask_ = 0;
      }
    }
  }

  u64 GetModulus() const noexcept { return p; }

  // 常量
  Fp Zero() const noexcept { return Fp{0}; }
  Fp One() const noexcept { return Fp{1 % p}; }

  // 将整数规约到 [0, p)
  Fp FromUint64(u64 x) const noexcept {
    if (is_mersenne_) {
      return Fp{reduce_mersenne(static_cast<u128>(x))};
    }
    return Fp{x % p};
  }

  // 将有符号整数规约到 [0, p)
  Fp FromInt64(std::int64_t x) const noexcept {
    if (is_mersenne_) {
      i128 xi = static_cast<i128>(x);
      bool neg = xi < 0;
      u128 mag = neg ? static_cast<u128>(-xi) : static_cast<u128>(xi);
      u64 r = reduce_mersenne(mag);
      if (neg && r != 0) r = p - r;
      return Fp{r};
    }

    i128 r = static_cast<i128>(x) % static_cast<i128>(p);
    if (r < 0) r += static_cast<i128>(p);
    return Fp{static_cast<u64>(r)};
  }

  // 基本谓词
  bool IsZero(Fp a) const noexcept { return a.v == 0; }
  bool Equal(Fp a, Fp b) const noexcept { return a.v == b.v; }

  // Optimized modular addition for canonical operands (0 <= a,b < p).
  // Avoids division/mod and is overflow-safe for any uint64 p.
  Fp Add(Fp a, Fp b) const noexcept {
    // r = a + b mod p
    // If a >= p-b then a+b-p else a+b
    const u64 threshold = p - b.v;  // in [1..p]
    const u64 r = (a.v >= threshold) ? (a.v - threshold) : (a.v + b.v);
    return Fp{r};
  }

  // Optimized modular subtraction for canonical operands (0 <= a,b < p).
  Fp Sub(Fp a, Fp b) const noexcept {
    if (a.v >= b.v) return Fp{a.v - b.v};
    // Here a < b, so a + (p-b) < p, no overflow.
    return Fp{a.v + (p - b.v)};
  }

  // -a (mod p)
  Fp Neg(Fp a) const noexcept {
    if (a.v == 0) return a;
    return Fp{p - a.v};
  }

  // a * b (mod p)
  Fp Mul(Fp a, Fp b) const noexcept {
    u128 t = static_cast<u128>(a.v) * static_cast<u128>(b.v);
    u64 r = is_mersenne_ ? reduce_mersenne(t) : static_cast<u64>(t % p);
    return Fp{r};
  }

  // a^2 (mod p)
  Fp Sqr(Fp a) const noexcept { return Mul(a, a); }

  // r + a*b (mod p) ——多项式/向量运算里很常用（先给个正确版本）
  Fp AddMul(Fp r, Fp a, Fp b) const noexcept { return Add(r, Mul(a, b)); }

  // 快速幂：a^e (mod p)
  Fp Pow(Fp a, u64 e) const noexcept {
    Fp base = a;
    Fp res = One();
    u64 exp = e;

    while (exp > 0) {
      if (exp & 1ULL) res = Mul(res, base);
      exp >>= 1ULL;
      if (exp) base = Sqr(base);
    }
    return res;
  }

  // 逆元：a^{-1} (mod p)
  // 由于 p 是素数，使用费马小定理：a^(p-2) mod p
  Fp Inv(Fp a) const {
    YACL_ENFORCE(!IsZero(a), "FpContext::Inv: inverse of zero");
    // p=2 时，p-2=0，inv(1)=1 也成立
    return Pow(a, p - 2);
  }

  // 除法：a / b = a * inv(b)
  Fp Div(Fp a, Fp b) const { return Mul(a, Inv(b)); }

  // In-place batch inversion:
  // input:  vec[i] in F_p, all must be non-zero
  // output: vec[i] = inv(vec[i])
  //
  // Complexity: O(n) mul + 1 inv
  void BatchInv(std::vector<Fp>& vec) const {
    const std::size_t n = vec.size();
    if (n == 0) return;

    // Check non-zero and canonicalize (defensive)
    for (auto& x : vec) {
      x.v %= p;
      YACL_ENFORCE(x.v != 0, "FpContext::BatchInv: zero element in batch");
    }

    // prefix products: pref[i] = vec[0]*...*vec[i]
    std::vector<Fp> pref(n);
    pref[0] = vec[0];
    for (std::size_t i = 1; i < n; ++i) {
      pref[i] = Mul(pref[i - 1], vec[i]);
    }

    // inv_total = 1 / (vec[0]*...*vec[n-1])
    Fp inv_total = Inv(pref[n - 1]);

    // Backward pass:
    // vec[i] = inv_total * pref[i-1]
    // inv_total *= old vec[i]
    for (std::size_t i = n; i-- > 0;) {
      Fp before = (i == 0) ? One() : pref[i - 1];
      Fp old = vec[i];

      vec[i] = Mul(inv_total, before);
      inv_total = Mul(inv_total, old);
    }
  }

 private:
  // Fast reduction for Mersenne prime p = 2^k - 1.
  inline u64 reduce_mersenne(u128 x) const noexcept {
    // Fold: (low k bits) + (rest), repeat once; final result < 2^k + 1 <= 2p
    const u128 mask = static_cast<u128>(mersenne_mask_);
    const unsigned k = mersenne_k_;

    u128 t = (x & mask) + (x >> k);
    u64 r = static_cast<u64>((t & mask) + (t >> k));
    if (r >= mersenne_mask_) r -= mersenne_mask_;
    return r;
  }
};

// 方便用的比较运算（不依赖 ctx；仅比较存储值）
inline bool operator==(Fp a, Fp b) noexcept { return a.v == b.v; }
inline bool operator!=(Fp a, Fp b) noexcept { return a.v != b.v; }

}  // namespace yacl::crypto::experimental::poly
