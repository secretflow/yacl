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

#include "yacl/crypto/experimental/poly/fp_poly.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cmath>
#include <cstdint>
#include <utility>
#include <vector>

#ifdef BIGNUM_WITH_GMP
#include "yacl/math/bigint/gmp/gmp_loader.h"
#endif

namespace yacl::crypto::experimental::poly {
namespace {

namespace detail {

using u32 = std::uint32_t;
using u64 = std::uint64_t;
using u128 = ::uint128_t;

struct NTTPrime {
  u32 mod;
  u32 primitive_root;
  int max_base;  // supports length up to 2^max_base
};

// 5 primes => product ~ 2^148.29, 覆盖 n<=2^20、p<2^64 的卷积上界
constexpr std::array<NTTPrime, 5> kNTT = {{
    {469762049U, 3U, 26},   // 7*2^26+1
    {754974721U, 11U, 24},  // 45*2^24+1
    {998244353U, 3U, 23},   // 119*2^23+1
    {1224736769U, 3U, 24},  // 73*2^24+1
    {1004535809U, 3U, 21},  // 479*2^21+1
}};

// -------------------- [LAZY REDUCTION] keep values in [0, 2*mod)
// --------------------
u32 add_mod_lazy2(u32 a, u32 b, u32 mod2) {
  // pre: a in [0, mod2), b in [0, mod)
  u32 s = a + b;  // < 3*mod < 2^32
  if (s >= mod2) {
    s -= mod2;
  }
  return s;  // in [0, mod2)
}

u32 sub_mod_lazy2(u32 a, u32 b, u32 mod, u32 mod2) {
  // pre: a in [0, mod2), b in [0, mod)
  // use a + mod - b to avoid potential overflow of a + mod2
  u32 s = a + mod - b;  // < 3*mod < 2^32
  if (s >= mod2) {
    s -= mod2;
  }
  return s;  // in [0, mod2)
}

// -------------------- [BARRETT] fast mod for u64 x with 32-bit prime mod
// --------------------
u32 barrett_reduce_u64(u64 x, u32 mod, u64 im) {
  // im = floor(2^64 / mod)
  const u64 q = static_cast<u64>((static_cast<u128>(x) * im) >> 64);
  u64 r = x - q * static_cast<u64>(mod);  // r in [0, 2*mod)
  if (r >= mod) {
    r -= mod;
  }
  if (r >= mod) {
    r -= mod;
  }
  return static_cast<u32>(r);
}

u32 mul_mod_barrett(u32 a, u32 b, u32 mod, u64 im) {
  return barrett_reduce_u64(static_cast<u64>(a) * static_cast<u64>(b), mod, im);
}

u32 pow_mod(u32 a, u64 e, u32 mod) {
  u64 r = 1;
  u64 x = a;
  while (e != 0U) {
    if ((e & 1) != 0U) {
      r = (r * x) % mod;
    }
    x = (x * x) % mod;
    e >>= 1;
  }
  return static_cast<u32>(r);
}

u32 inv_mod(u32 a, u32 mod) {
  // mod is prime
  return pow_mod(a, static_cast<u64>(mod) - 2, mod);
}

// -------------------- [BITREV CACHE] --------------------
// Cache bit-reversal permutation tables by logn (independent of modulus).
const std::vector<u32>& bitrev_table(u32 n) {
  YACL_ENFORCE(n != 0 && (n & (n - 1)) == 0,
               "bitrev_table: n must be power-of-two");
  const int logn = absl::countr_zero(n);

  struct RevCache {
    std::array<std::vector<u32>, 32> tab;
  };
  static thread_local RevCache C;

  auto& rev = C.tab[logn];
  if (rev.size() == n) {
    return rev;
  }

  rev.resize(n);
  rev[0] = 0;
  // rev[i] = (rev[i>>1] >> 1) | ((i&1) << (logn-1))
  for (u32 i = 1; i < n; ++i) {
    rev[i] = (rev[i >> 1] >> 1) | ((i & 1U) << (logn - 1));
  }
  return rev;
}

struct NTTCache {
  u32 mod = 0;
  u32 primitive_root = 0;
  int max_base = 0;

  u64 barrett_im = 0;  // floor(2^64 / mod)

  u32 cache_n = 0;         // power of two
  std::vector<u32> root;   // size cache_n: base^i
  std::vector<u32> iroot;  // size cache_n: inv(base)^i

  // inv_n_by_log[log] = inv(2^log) mod mod
  std::array<u32, 32> inv_n_by_log{};
  int inv_ready_upto = -1;  // max log filled
};

void build_root_table(NTTCache& c, u32 new_n) {
  // new_n must be power-of-two and <= 2^max_base
  YACL_ENFORCE(new_n != 0 && (new_n & (new_n - 1)) == 0,
               "NTT cache: new_n must be power-of-two");
  int logn = absl::countr_zero(new_n);
  YACL_ENFORCE(logn <= c.max_base,
               "NTT cache: required N exceeds prime capability");

  c.cache_n = new_n;
  c.root.assign(new_n, 0);
  c.iroot.assign(new_n, 0);

  // base = g^((mod-1)/N)
  const u32 base =
      pow_mod(c.primitive_root,
              static_cast<u64>(c.mod - 1) / static_cast<u64>(new_n), c.mod);
  const u32 ibase = inv_mod(base, c.mod);

  c.root[0] = 1;
  for (u32 i = 1; i < new_n; ++i) {
    c.root[i] = mul_mod_barrett(c.root[i - 1], base, c.mod, c.barrett_im);
  }

  c.iroot[0] = 1;
  for (u32 i = 1; i < new_n; ++i) {
    c.iroot[i] = mul_mod_barrett(c.iroot[i - 1], ibase, c.mod, c.barrett_im);
  }

  // inv_n table (fill up to logn)
  for (int k = 0; k <= logn; ++k) {
    const u32 n_k = static_cast<u32>(1U) << k;
    c.inv_n_by_log[k] = inv_mod(n_k, c.mod);
  }
  c.inv_ready_upto = logn;
}

// Ensure cache has root tables for at least n (power of two)
NTTCache& ensure_ntt_cache(std::size_t prime_idx, u32 n) {
  static thread_local std::array<NTTCache, kNTT.size()> caches;

  NTTCache& C = caches[prime_idx];
  const auto prm = kNTT[prime_idx];

  if (C.mod == 0) {
    C.mod = prm.mod;
    C.primitive_root = prm.primitive_root;
    C.max_base = prm.max_base;
    C.cache_n = 0;
    C.inv_ready_upto = -1;

    // [BARRETT] im = floor(2^64 / mod)
    C.barrett_im = static_cast<u64>((static_cast<u128>(1) << 64) /
                                    static_cast<u128>(C.mod));
  }

  YACL_ENFORCE(C.mod == prm.mod, "NTT cache: modulus mismatch");

  YACL_ENFORCE(n != 0 && (n & (n - 1)) == 0,
               "NTT cache: n must be power-of-two");

  // If cache_n is smaller than needed, rebuild to exactly n
  if (C.cache_n < n) {
    build_root_table(C, n);
    return C;
  }

  // inv table might be too short if cache was built larger but inv_ready_upto
  // not filled
  int logn = absl::countr_zero(n);
  if (C.inv_ready_upto < logn) {
    for (int k = C.inv_ready_upto + 1; k <= logn; ++k) {
      const u32 n_k = static_cast<u32>(1U) << k;
      C.inv_n_by_log[k] = inv_mod(n_k, C.mod);
    }
    C.inv_ready_upto = logn;
  }

  return C;
}

// Cached NTT: no pow_mod in hot path
void ntt_cached(std::size_t prime_idx, std::vector<u32>& a, bool invert) {
  const u32 n = static_cast<u32>(a.size());
  NTTCache& C = ensure_ntt_cache(prime_idx, n);
  const u32 mod = C.mod;
  const u32 mod2 = mod + mod;
  const u64 im = C.barrett_im;
  const u32 cache_n = C.cache_n;

#ifndef NDEBUG
  // Debug safeguard: keep inputs in [0, mod)
  for (u32 i = 0; i < n; ++i) {
    if (a[i] >= mod) {
      a[i] %= mod;
    }
  }
#endif

  // bit-reversal
  const auto& rev = bitrev_table(n);
  for (u32 i = 0; i < n; ++i) {
    const u32 j = rev[i];
    if (i < j) {
      std::swap(a[i], a[j]);
    }
  }

  u32* A = a.data();

  // Twiddle table pointer: root[idx] = base^idx, iroot similarly.
  const u32* RT = invert ? C.iroot.data() : C.root.data();

  for (u32 len = 2; len <= n; len <<= 1) {
    const u32 half = len >> 1;
    const u32 step = cache_n / len;  // twiddle index stride in root table

    for (u32 blk = 0; blk < n; blk += len) {
      u32* p = A + blk;
      u32* q = p + half;

      u32 j = 0;
      u32 idx = 0;

      // 4-way unroll: load w from table, no w update mul
      for (; j + 4 <= half; j += 4, idx += 4 * step) {
        const u32 w0 = RT[idx];
        const u32 w1 = RT[idx + step];
        const u32 w2 = RT[idx + 2 * step];
        const u32 w3 = RT[idx + 3 * step];

        const u32 u0 = p[j + 0];
        const u32 u1 = p[j + 1];
        const u32 u2 = p[j + 2];
        const u32 u3 = p[j + 3];

        const u32 v0 = barrett_reduce_u64(
            static_cast<u64>(w0) * static_cast<u64>(q[j + 0]), mod, im);
        const u32 v1 = barrett_reduce_u64(
            static_cast<u64>(w1) * static_cast<u64>(q[j + 1]), mod, im);
        const u32 v2 = barrett_reduce_u64(
            static_cast<u64>(w2) * static_cast<u64>(q[j + 2]), mod, im);
        const u32 v3 = barrett_reduce_u64(
            static_cast<u64>(w3) * static_cast<u64>(q[j + 3]), mod, im);

        p[j + 0] = add_mod_lazy2(u0, v0, mod2);
        q[j + 0] = sub_mod_lazy2(u0, v0, mod, mod2);

        p[j + 1] = add_mod_lazy2(u1, v1, mod2);
        q[j + 1] = sub_mod_lazy2(u1, v1, mod, mod2);

        p[j + 2] = add_mod_lazy2(u2, v2, mod2);
        q[j + 2] = sub_mod_lazy2(u2, v2, mod, mod2);

        p[j + 3] = add_mod_lazy2(u3, v3, mod2);
        q[j + 3] = sub_mod_lazy2(u3, v3, mod, mod2);
      }

      // tail
      for (; j < half; ++j, idx += step) {
        const u32 w = RT[idx];
        const u32 u = p[j];
        const u32 v = barrett_reduce_u64(
            static_cast<u64>(w) * static_cast<u64>(q[j]), mod, im);

        p[j] = add_mod_lazy2(u, v, mod2);
        q[j] = sub_mod_lazy2(u, v, mod, mod2);
      }
    }
  }

  if (invert) {
    const int logn = absl::countr_zero(n);
    const u32 inv_n = C.inv_n_by_log[logn];

    // Normalize [0,2mod) -> [0,mod), then scale to [0,mod)
    for (u32 i = 0; i < n; ++i) {
      u32 x = A[i];
      if (x >= mod) {
        x -= mod;
      }
      A[i] = barrett_reduce_u64(static_cast<u64>(x) * static_cast<u64>(inv_n),
                                mod, im);
    }
  }
}

// -------------------- [CONV SCRATCH] reuse fb buffer per prime
// --------------------
struct NTTConvScratch {
  std::vector<u32> fb;
};

NTTConvScratch& conv_scratch(std::size_t prime_idx) {
  static thread_local std::array<NTTConvScratch, kNTT.size()> S;
  return S[prime_idx];
}

// Compute convolution into `fa` (fa is also the NTT working buffer and final
// output).
void convolution_mod_ntt_into(std::vector<u32>& fa, const std::vector<u32>& a,
                              const std::vector<u32>& b,
                              std::size_t prime_idx) {
  if (a.empty() || b.empty()) {
    fa.clear();
    return;
  }

  const auto prm = kNTT[prime_idx];

  std::size_t need = a.size() + b.size() - 1;
  std::size_t ntt_n = 1;
  while (ntt_n < need) {
    ntt_n <<= 1;
  }

  if (static_cast<int>(absl::countr_zero(
          static_cast<unsigned long long>(ntt_n))) > prm.max_base) {
    YACL_THROW_ARGUMENT_ERROR(
        "convolution_mod_ntt_into: NTT length exceeds prime capability");
  }

  // Ensure NTT plan exists and get Barrett constants / mod
  NTTCache& C = ensure_ntt_cache(prime_idx, static_cast<u32>(ntt_n));
  const u32 mod = C.mod;

  // fa: output + working buffer (reuse caller's capacity)
  fa.resize(ntt_n);
  std::copy(a.begin(), a.end(), fa.begin());
  if (a.size() < ntt_n) {
    std::fill(fa.begin() + a.size(), fa.end(), 0U);  // only clear the tail
  }

  // fb: scratch buffer (thread_local reuse)
  auto& S = conv_scratch(prime_idx);
  S.fb.resize(ntt_n);
  std::copy(b.begin(), b.end(), S.fb.begin());
  if (b.size() < ntt_n) {
    std::fill(S.fb.begin() + b.size(), S.fb.end(), 0U);  // only clear the tail
  }

  ntt_cached(prime_idx, fa, false);
  ntt_cached(prime_idx, S.fb, false);

  for (std::size_t i = 0; i < ntt_n; ++i) {
    fa[i] = mul_mod_barrett(fa[i], S.fb[i], mod, C.barrett_im);
  }

  ntt_cached(prime_idx, fa, true);

  fa.resize(need);
}

// =========================================================================================
// [NTT-64] 3×64-bit primes (each has 2^21 factor) for large p (e.g., M61) to
// reduce CRT cost
// =========================================================================================
struct NTT64Prime {
  u64 mod;
  u64 primitive_root;
  int max_base;  // supports length up to 2^max_base
};

// product ~ 2^180 >> bound for p<=2^61, n<=2^20
constexpr std::array<NTT64Prime, 3> kNTT64 = {{
    {508655436684066817ULL, 5ULL, 21},    // 5 * 2^21 * 80848604311 + 1
    {1072774856935735297ULL, 10ULL, 21},  // 10 * 2^21 * 3479856559 + 1
    {841916508553609217ULL, 3ULL,
     21},  // 3 * 2^21 * 8006563 * 7 * 13 * 19 * 29 + 1
}};

u64 mul_mod64(u64 a, u64 b, u64 mod) {
  return static_cast<u64>(static_cast<u128>(a) * static_cast<u128>(b) %
                          static_cast<u128>(mod));
}

u64 pow_mod64(u64 a, u64 e, u64 mod) {
  u64 r = 1;
  u64 x = a;
  while (e != 0U) {
    if ((e & 1) != 0U) {
      r = mul_mod64(r, x, mod);
    }
    x = mul_mod64(x, x, mod);
    e >>= 1;
  }
  return r;
}

u64 inv_mod64(u64 a, u64 mod) { return pow_mod64(a, mod - 2, mod); }

struct NTT64Cache {
  u64 mod = 0;
  u64 primitive_root = 0;
  int max_base = 0;
  u32 cache_n = 0;  // root/iroot length
  int inv_ready_upto = -1;
  std::array<u64, 32> inv_n_by_log{};
  std::vector<u64> root;
  std::vector<u64> iroot;
};

void build_root_table64(NTT64Cache& c, u32 n) {
  if (n == c.cache_n) {
    return;
  }

  const int logn = absl::countr_zero(n);
  if (logn > c.max_base) {
    YACL_THROW_ARGUMENT_ERROR("NTT64 cache: n exceeds max_base");
  }

  // compute base = primitive_root^{(mod-1)/n} (primitive n-th root)
  const u64 base = pow_mod64(c.primitive_root, (c.mod - 1) / n, c.mod);
  const u64 ibase = inv_mod64(base, c.mod);

  c.cache_n = n;
  c.root.resize(n);
  c.iroot.resize(n);
  c.root[0] = 1;
  for (u32 i = 1; i < n; ++i) {
    c.root[i] = mul_mod64(c.root[i - 1], base, c.mod);
  }

  c.iroot[0] = 1;
  for (u32 i = 1; i < n; ++i) {
    c.iroot[i] = mul_mod64(c.iroot[i - 1], ibase, c.mod);
  }

  for (int k = 0; k <= logn; ++k) {
    const u32 n_k = static_cast<u32>(1U) << k;
    c.inv_n_by_log[k] = inv_mod64(n_k, c.mod);
  }
  c.inv_ready_upto = logn;
}

NTT64Cache& ensure_ntt64_cache(std::size_t prime_idx, u32 n) {
  static thread_local std::array<NTT64Cache, kNTT64.size()> caches;

  NTT64Cache& C = caches[prime_idx];
  const auto prm = kNTT64[prime_idx];

  if (C.mod == 0) {
    C.mod = prm.mod;
    C.primitive_root = prm.primitive_root;
    C.max_base = prm.max_base;
    C.cache_n = 0;
    C.inv_ready_upto = -1;
  }

  YACL_ENFORCE(C.mod == prm.mod, "NTT64 cache: modulus mismatch");
  YACL_ENFORCE(n != 0 && (n & (n - 1)) == 0,
               "NTT64 cache: n must be power-of-two");

  if (C.cache_n < n) {
    build_root_table64(C, n);
    return C;
  }

  int logn = absl::countr_zero(n);
  if (C.inv_ready_upto < logn) {
    for (int k = C.inv_ready_upto + 1; k <= logn; ++k) {
      const u32 n_k = static_cast<u32>(1U) << k;
      C.inv_n_by_log[k] = inv_mod64(n_k, C.mod);
    }
    C.inv_ready_upto = logn;
  }

  return C;
}

void ntt64_cached(std::size_t prime_idx, std::vector<u64>& a, bool invert) {
  const u32 n = static_cast<u32>(a.size());
  NTT64Cache& C = ensure_ntt64_cache(prime_idx, n);
  const u64 mod = C.mod;
  const u64 mod2 = mod + mod;
  const u32 cache_n = C.cache_n;

#ifndef NDEBUG
  for (u32 i = 0; i < n; ++i) {
    if (a[i] >= mod) {
      a[i] %= mod;
    }
  }
#endif

  const auto& rev = bitrev_table(n);
  for (u32 i = 0; i < n; ++i) {
    const u32 j = rev[i];
    if (i < j) {
      std::swap(a[i], a[j]);
    }
  }

  u64* A = a.data();
  const u64* RT = invert ? C.iroot.data() : C.root.data();

  for (u32 len = 2; len <= n; len <<= 1) {
    const u32 half = len >> 1;
    const u32 step = cache_n / len;

    for (u32 blk = 0; blk < n; blk += len) {
      u64* p = A + blk;
      u64* q = p + half;

      u32 idx = 0;
      for (u32 j = 0; j < half; ++j) {
        u64 x = p[j];
        u64 y = mul_mod64(q[j], RT[idx], mod);

        u64 u = x + y;
        if (u >= mod2) {
          u -= mod2;
        }

        u64 v = x + mod - y;
        if (v >= mod2) {
          v -= mod2;
        }

        p[j] = u;
        q[j] = v;
        idx += step;
      }
    }
  }

  if (invert) {
    const int logn = absl::countr_zero(n);
    const u64 inv_n = C.inv_n_by_log[logn];

    for (u32 i = 0; i < n; ++i) {
      u64 x = a[i];
      if (x >= mod) {
        x -= mod;
      }
      a[i] = mul_mod64(x, inv_n, mod);
    }
  }
}

struct NTT64ConvScratch {
  std::vector<u64> fb;
};

NTT64ConvScratch& conv64_scratch(std::size_t prime_idx) {
  static thread_local std::array<NTT64ConvScratch, kNTT64.size()> S;
  return S[prime_idx];
}

void convolution_mod_ntt64_into(std::vector<u64>& out,
                                const std::vector<u64>& a,
                                const std::vector<u64>& b,
                                std::size_t prime_idx) {
  if (a.empty() || b.empty()) {
    out.clear();
    return;
  }

  const auto prm = kNTT64[prime_idx];

  std::size_t need = a.size() + b.size() - 1;
  std::size_t ntt_n = 1;
  while (ntt_n < need) {
    ntt_n <<= 1;
  }

  if (static_cast<int>(absl::countr_zero(
          static_cast<unsigned long long>(ntt_n))) > prm.max_base) {
    YACL_THROW_ARGUMENT_ERROR(
        "convolution_mod_ntt64_into: NTT length exceeds prime capability");
  }

  NTT64Cache& C = ensure_ntt64_cache(prime_idx, static_cast<u32>(ntt_n));
  const u64 mod = C.mod;

  out.resize(ntt_n);
  std::copy(a.begin(), a.end(), out.begin());
  if (a.size() < ntt_n) {
    std::fill(out.begin() + a.size(), out.end(), 0U);
  }

  auto& S = conv64_scratch(prime_idx);
  S.fb.resize(ntt_n);
  std::copy(b.begin(), b.end(), S.fb.begin());
  if (b.size() < ntt_n) {
    std::fill(S.fb.begin() + b.size(), S.fb.end(), 0U);
  }

  ntt64_cached(prime_idx, out, false);
  ntt64_cached(prime_idx, S.fb, false);

  for (std::size_t i = 0; i < ntt_n; ++i) {
    out[i] = mul_mod64(out[i], S.fb[i], mod);
  }

  ntt64_cached(prime_idx, out, true);
  out.resize(need);
}

// CRT for 3×64-bit primes -> modulo target p (u64)
struct CRT3Plan64 {
  u64 p = 0;
  std::array<u64, 3> m{};
  u64 inv_m0_mod_m1 = 0;
  u64 inv_m01_mod_m2 = 0;
  u128 M01 = 0;
  u64 m0_mod_p = 0;
  u64 m0m1_mod_p = 0;

  CRT3Plan64() = default;
  explicit CRT3Plan64(u64 mod_p) : p(mod_p) {
    for (int i = 0; i < 3; ++i) {
      m[i] = kNTT64[i].mod;
    }
    inv_m0_mod_m1 = inv_mod64(m[0] % m[1], m[1]);
    M01 = static_cast<u128>(m[0]) * static_cast<u128>(m[1]);
    inv_m01_mod_m2 = inv_mod64(static_cast<u64>(M01 % m[2]), m[2]);

    m0_mod_p = static_cast<u64>(static_cast<u128>(m[0]) % static_cast<u128>(p));
    m0m1_mod_p = static_cast<u64>(M01 % static_cast<u128>(p));
  }

  u64 combine_to_mod_p(const u64* r3) const {
    // Garner style: x = r0 + m0*t1 + m0*m1*t2
    u64 t1 = r3[1] >= r3[0] ? (r3[1] - r3[0]) : (r3[1] + m[1] - (r3[0] % m[1]));
    t1 = static_cast<u64>(static_cast<u128>(t1) *
                          static_cast<u128>(inv_m0_mod_m1) %
                          static_cast<u128>(m[1]));

    u64 r01 = r3[0] +
              static_cast<u64>(static_cast<u128>(m[0]) * static_cast<u128>(t1) %
                               static_cast<u128>(m[2]));
    r01 %= m[2];

    u64 t2 = r3[2] >= r01 ? (r3[2] - r01) : (r3[2] + m[2] - r01);
    t2 = static_cast<u64>(static_cast<u128>(t2) *
                          static_cast<u128>(inv_m01_mod_m2) %
                          static_cast<u128>(m[2]));

    const u64 term0 = r3[0] % p;
    const u64 term1 =
        static_cast<u64>(static_cast<u128>(m0_mod_p) * static_cast<u128>(t1) %
                         static_cast<u128>(p));
    const u64 term2 =
        static_cast<u64>(static_cast<u128>(m0m1_mod_p) % static_cast<u128>(p) *
                         static_cast<u128>(t2) % static_cast<u128>(p));

    u64 res = term0 + term1;
    if (res >= p) {
      res -= p;
    }
    res += term2;
    if (res >= p) {
      res -= p;
    }
    return res;
  }
};

std::size_t select_prime_count64(u64 p, std::size_t min_dim) {
  (void)p;
  if (min_dim == 0) {
    return 3;
  }
  const double log_bound = std::log2(static_cast<double>(min_dim)) +
                           2.0 * std::log2(static_cast<double>(p));
  double log_prod3 = 0.0;
  for (int i = 0; i < 3; ++i) {
    log_prod3 += std::log2(static_cast<double>(kNTT64[i].mod));
  }
  if (log_bound + 2.0 <= log_prod3) {
    return 3;
  }
  YACL_THROW_ARGUMENT_ERROR(
      "select_prime_count64: coefficient bound exceeds 3 wide primes");
}

// Forward decl for CRT3Plan
u128 crt3_u128(u32 r0, u32 r1, u32 r2, u32 m0, u32 m1, u32 m2,
               u32 inv_m0_mod_m1, u32 inv_m01_mod_m2, u128 M01);

// Decide how many NTT primes are needed to cover coefficient bound.
// bound ~ min(n,m) * (p-1)^2; we use log2 to compare.
std::size_t select_prime_count(u64 p, std::size_t min_dim) {
  if (min_dim == 0) {
    return 3;  // unused path guard
  }

  const double log_bound = std::log2(static_cast<double>(min_dim)) +
                           2.0 * std::log2(static_cast<double>(p));

  static const double log_prod3 = []() {
    double s = 0.0;
    for (int i = 0; i < 3; ++i) {
      s += std::log2(static_cast<double>(kNTT[i].mod));
    }
    return s;
  }();

  // two bits of slack to be conservative
  if (log_bound + 2.0 <= log_prod3) {
    return 3;
  }
  return kNTT.size();  // fall back to all primes (5 today)
}

// -------------------- [CRT5] specialized CRT combiner for exactly 5 NTT primes
// --------------------
struct CRT5Precomp {
  static constexpr int K = 5;
  std::array<u32, K> m{};

  // groupA: m0,m1,m2
  u32 inv_m0_mod_m1 = 0;
  u32 inv_m01_mod_m2 = 0;
  u128 M01 = 0;
  u128 M012 = 0;

  // groupB: m3,m4
  u32 inv_m3_mod_m4 = 0;
  u128 M34 = 0;

  // inv(M012) mod m3/m4
  u32 inv_M012_mod_m3 = 0;
  u32 inv_M012_mod_m4 = 0;

  CRT5Precomp() {
    static_assert(kNTT.size() == 5,
                  "CRT5Precomp requires exactly 5 NTT primes");

    for (int i = 0; i < K; ++i) {
      m[i] = kNTT[i].mod;
    }

    // groupA
    inv_m0_mod_m1 = inv_mod(static_cast<u32>(m[0] % m[1]), m[1]);
    M01 = static_cast<u128>(m[0]) * static_cast<u128>(m[1]);
    inv_m01_mod_m2 = inv_mod(static_cast<u32>(M01 % m[2]), m[2]);
    M012 = M01 * static_cast<u128>(m[2]);

    // groupB
    inv_m3_mod_m4 = inv_mod(static_cast<u32>(m[3] % m[4]), m[4]);
    M34 = static_cast<u128>(m[3]) * static_cast<u128>(m[4]);

    inv_M012_mod_m3 = inv_mod(static_cast<u32>(M012 % m[3]), m[3]);
    inv_M012_mod_m4 = inv_mod(static_cast<u32>(M012 % m[4]), m[4]);
  }
};

const CRT5Precomp& crt5_precomp() {
  static const CRT5Precomp pc;
  return pc;
}

// CRT for first 3 primes -> modulo target p (u64)
struct CRT3Plan {
  u64 p = 0;
  std::array<u32, 3> m{};
  u32 inv_m0_mod_m1 = 0;
  u32 inv_m01_mod_m2 = 0;
  u128 M01 = 0;

  CRT3Plan() = default;
  explicit CRT3Plan(u64 mod_p) : p(mod_p) {
    const auto& pc = crt5_precomp();  // reuse first three parameters
    for (int i = 0; i < 3; ++i) {
      m[i] = pc.m[i];
    }
    inv_m0_mod_m1 = pc.inv_m0_mod_m1;
    inv_m01_mod_m2 = pc.inv_m01_mod_m2;
    M01 = pc.M01;
  }

  u64 combine_to_mod_p(const u32* r3) const {
    const auto& pc = crt5_precomp();
    u128 a = crt3_u128(r3[0], r3[1], r3[2], pc.m[0], pc.m[1], pc.m[2],
                       pc.inv_m0_mod_m1, pc.inv_m01_mod_m2, pc.M01);
    return static_cast<u64>(a % static_cast<u128>(p));
  }
};

// CRT for 3 primes -> u128 in [0, m0*m1*m2)
u128 crt3_u128(u32 r0, u32 r1, u32 r2, u32 m0, u32 m1, u32 m2,
               u32 inv_m0_mod_m1, u32 inv_m01_mod_m2, u128 M01) {
  // x = r0 + m0 * t1  (mod m0*m1)
  u32 t1 = (r1 >= r0) ? (r1 - r0) : (r1 + m1 - static_cast<u32>(r0 % m1));
  t1 = static_cast<u32>(static_cast<u64>(t1) * inv_m0_mod_m1 % m1);
  u128 x =
      static_cast<u128>(r0) + static_cast<u128>(m0) * static_cast<u128>(t1);

  // x = x + (m0*m1) * t2  (mod m0*m1*m2)
  u32 x_mod_m2 = static_cast<u32>(x % m2);
  u32 t2 = (r2 >= x_mod_m2) ? (r2 - x_mod_m2) : (r2 + m2 - x_mod_m2);
  t2 = static_cast<u32>(static_cast<u64>(t2) * inv_m01_mod_m2 % m2);
  x += M01 * static_cast<u128>(t2);
  return x;
}

// CRT for 2 primes -> u128 in [0, m3*m4)
u128 crt2_u128(u32 r3, u32 r4, u32 m3, u32 m4, u32 inv_m3_mod_m4) {
  u32 t = (r4 >= r3) ? (r4 - r3) : (r4 + m4 - static_cast<u32>(r3 % m4));
  t = static_cast<u32>(static_cast<u64>(t) * inv_m3_mod_m4 % m4);
  return static_cast<u128>(r3) + static_cast<u128>(m3) * static_cast<u128>(t);
}

struct CRT5Plan {
  u64 p = 0;
  u64 M012_mod_p = 0;

  CRT5Plan() = default;
  explicit CRT5Plan(u64 mod_p) : p(mod_p) {
    const auto& pc = crt5_precomp();
    M012_mod_p = static_cast<u64>(pc.M012 % static_cast<u128>(p));
  }

  u64 combine_to_mod_p(const u32* r5) const {
    const auto& pc = crt5_precomp();

    // a in [0, M012)
    const u128 a = crt3_u128(r5[0], r5[1], r5[2], pc.m[0], pc.m[1], pc.m[2],
                             pc.inv_m0_mod_m1, pc.inv_m01_mod_m2, pc.M01);

    // t ≡ (r - a) * inv(M012) (mod m3, m4)
    const u32 a_mod_m3 = static_cast<u32>(a % pc.m[3]);
    const u32 a_mod_m4 = static_cast<u32>(a % pc.m[4]);

    u32 t3 =
        (r5[3] >= a_mod_m3) ? (r5[3] - a_mod_m3) : (r5[3] + pc.m[3] - a_mod_m3);
    u32 t4 =
        (r5[4] >= a_mod_m4) ? (r5[4] - a_mod_m4) : (r5[4] + pc.m[4] - a_mod_m4);

    t3 = static_cast<u32>(static_cast<u64>(t3) * pc.inv_M012_mod_m3 % pc.m[3]);
    t4 = static_cast<u32>(static_cast<u64>(t4) * pc.inv_M012_mod_m4 % pc.m[4]);

    const u128 t = crt2_u128(t3, t4, pc.m[3], pc.m[4], pc.inv_m3_mod_m4);

    // x = a + M012 * t (mod p)
    const u64 a_mod_p = static_cast<u64>(a % static_cast<u128>(p));
    const u64 t_mod_p = static_cast<u64>(t % static_cast<u128>(p));
    const u64 add =
        static_cast<u64>(static_cast<u128>(M012_mod_p) *
                         static_cast<u128>(t_mod_p) % static_cast<u128>(p));

    u64 res = a_mod_p + add;
    if (res >= p) {
      res -= p;
    }
    return res;
  }
};

#ifdef BIGNUM_WITH_GMP
unsigned choose_base_bits(u64 modulus, std::size_t min_len) {
  // max coeff <= min_len * (p-1)^2. Add a couple safety bits.
  double lp = std::log2(static_cast<double>(modulus));
  double bound =
      2.0 * lp +
      std::log2(static_cast<double>(std::max<std::size_t>(min_len, 1))) + 2.0;
  unsigned bits = static_cast<unsigned>(std::ceil(bound));
  if (bits < 16) bits = 16;
  return bits;
}

mp_limb_t mask_bits(unsigned bits) {
  if (bits == 0) return 0;
  if (bits >= GMP_NUMB_BITS) return ~(mp_limb_t)0;
  return ((mp_limb_t)1 << bits) - 1;
}

struct PackScratch {
  std::vector<u64> pow2;  // 2^k mod p for current base_bits/mod
  unsigned pow_bits = 0;
  u64 pow_mod = 0;

  void ensure_pow2(unsigned bits, u64 mod) {
    if (pow_bits == bits && pow_mod == mod && !pow2.empty()) return;
    pow_bits = bits;
    pow_mod = mod;
    pow2.assign(bits + 1, 0);
    pow2[0] = 1 % mod;
    for (unsigned i = 1; i <= bits; ++i) {
      pow2[i] = (u64)((u128)pow2[i - 1] * 2 % mod);
    }
  }
};

struct MpnScratch {
  std::vector<mp_limb_t> A;
  std::vector<mp_limb_t> B;
  std::vector<mp_limb_t> C;
};

mp_size_t pack_poly_bits(std::vector<mp_limb_t>& out,
                         const std::vector<Fp>& coeffs, unsigned base_bits) {
  if (coeffs.empty()) {
    out.clear();
    return 0;
  }

  const unsigned limb_bits = GMP_NUMB_BITS;
  const unsigned limbs_per_coeff =
      (base_bits % limb_bits == 0) ? (base_bits / limb_bits) : 0;
  if (limbs_per_coeff > 0) {
    const std::size_t limb_count = coeffs.size() * (std::size_t)limbs_per_coeff;
    out.assign(limb_count, 0);
    for (std::size_t i = 0; i < coeffs.size(); ++i) {
      out[i * (std::size_t)limbs_per_coeff] = (mp_limb_t)coeffs[i].v;
    }
    mp_size_t used = (mp_size_t)limb_count;
    while (used > 0 && out[(std::size_t)used - 1] == 0) --used;
    if (used == 0) used = 1;
    return used;
  }

  const std::size_t total_bits =
      (std::size_t)coeffs.size() * (std::size_t)base_bits;
  const std::size_t limb_count = (total_bits + limb_bits - 1) / limb_bits;

  out.assign(limb_count, 0);

  for (std::size_t i = 0; i < coeffs.size(); ++i) {
    u128 val = (u128)coeffs[i].v;
    std::size_t bitpos = (std::size_t)i * (std::size_t)base_bits;
    std::size_t idx = bitpos / limb_bits;
    unsigned offset = (unsigned)(bitpos % limb_bits);

    unsigned consumed = 0;
    unsigned bits_left = base_bits;
    while (bits_left > 0) {
      const unsigned take = std::min<unsigned>(bits_left, limb_bits - offset);
      mp_limb_t chunk = 0;
      if (consumed < 128) {  // u128 width guard
        const unsigned safe_take = std::min<unsigned>(take, 128 - consumed);
        chunk = (mp_limb_t)((val >> consumed) & mask_bits(safe_take));
      }
      out[idx] |= (chunk << offset);

      consumed += take;
      bits_left -= take;
      ++idx;
      offset = 0;
    }
  }

  mp_size_t used = (mp_size_t)limb_count;
  while (used > 0 && out[(std::size_t)used - 1] == 0) --used;
  if (used == 0) used = 1;  // keep at least one limb live
  return used;
}

void unpack_poly_bits(std::vector<Fp>& out, const mp_limb_t* limbs,
                      mp_size_t limb_count, unsigned base_bits,
                      const FpContext& F, PackScratch& S) {
  const unsigned limb_bits = GMP_NUMB_BITS;
  const std::size_t limb_count_s =
      (limb_count > 0) ? (std::size_t)limb_count : 0;

  if (limb_count_s == 0 || limbs == nullptr) {
    for (auto& x : out) x = F.Zero();
    return;
  }

  const unsigned limbs_per_coeff =
      (base_bits % limb_bits == 0) ? (base_bits / limb_bits) : 0;
  if (limbs_per_coeff > 0) {
    const u64 mod = F.GetModulus();
    S.ensure_pow2(base_bits, mod);
    for (std::size_t i = 0; i < out.size(); ++i) {
      std::size_t idx = i * (std::size_t)limbs_per_coeff;
      if (idx >= limb_count_s) {
        out[i] = F.Zero();
        continue;
      }
      u64 acc_mod = 0;
      for (unsigned t = 0; t < limbs_per_coeff; ++t) {
        const std::size_t limb_idx = idx + t;
        if (limb_idx >= limb_count_s) break;
        const u64 limb = (u64)limbs[limb_idx];
        const unsigned bit = t * limb_bits;
        const u64 term = (u64)((u128)(limb % mod) * (u128)S.pow2[bit] % mod);
        acc_mod += term;
        if (acc_mod >= mod) acc_mod -= mod;
      }
      out[i] = F.FromUint64(acc_mod);
    }
    return;
  }

  const u64 mod = F.GetModulus();
  S.ensure_pow2(base_bits, mod);

  for (std::size_t i = 0; i < out.size(); ++i) {
    const std::size_t bitpos = (std::size_t)i * (std::size_t)base_bits;
    std::size_t idx = bitpos / limb_bits;
    if (idx >= limb_count_s) {
      out[i] = F.Zero();
      continue;
    }
    unsigned offset = (unsigned)(bitpos % limb_bits);

    unsigned collected = 0;
    u64 acc_mod = 0;
    while (collected < base_bits && idx < limb_count_s) {
      const unsigned take =
          std::min<unsigned>(base_bits - collected, limb_bits - offset);
      const mp_limb_t limb = limbs[idx];
      mp_limb_t chunk = limb >> offset;
      if (take < GMP_NUMB_BITS) {
        chunk &= mask_bits(take);
      }

      const u64 term =
          (u64)((u128)(chunk % mod) * (u128)S.pow2[collected] % mod);
      acc_mod += term;
      if (acc_mod >= mod) acc_mod -= mod;

      collected += take;
      ++idx;
      offset = 0;
    }

    out[i] = F.FromUint64(acc_mod);
  }
}

std::vector<Fp> mul_kronecker_coeffs(const FpContext& F,
                                     const std::vector<Fp>& a,
                                     const std::vector<Fp>& b) {
  if (a.empty() || b.empty()) return {};

  const auto& gmp = ::yacl::math::gmp::GMPLoader::Instance();
  YACL_ENFORCE(gmp.IsLoaded(), "GMP is not loaded");

  const std::size_t n = a.size();
  const std::size_t m = b.size();
  const std::size_t min_len = std::min(n, m);
  const unsigned base_bits = choose_base_bits(F.GetModulus(), min_len);

  static thread_local MpnScratch S;
  static thread_local PackScratch PS;

  const mp_size_t limbs_a = pack_poly_bits(S.A, a, base_bits);
  const mp_size_t limbs_b = pack_poly_bits(S.B, b, base_bits);

  struct MpzTriple {
    const ::yacl::math::gmp::GMPLoader& gmp;
    mpz_t a;
    mpz_t b;
    mpz_t c;

    explicit MpzTriple(const ::yacl::math::gmp::GMPLoader& g) : gmp(g) {
      gmp.mpz_init_(a);
      gmp.mpz_init_(b);
      gmp.mpz_init_(c);
    }

    ~MpzTriple() {
      gmp.mpz_clear_(a);
      gmp.mpz_clear_(b);
      gmp.mpz_clear_(c);
    }
  };

  MpzTriple Z(gmp);

  // Import packed limbs as non-negative big integers.
  gmp.mpz_import_(Z.a, static_cast<std::size_t>(limbs_a), /*order=*/-1,
                  sizeof(mp_limb_t), /*endian=*/0, /*nails=*/0, S.A.data());
  gmp.mpz_import_(Z.b, static_cast<std::size_t>(limbs_b), /*order=*/-1,
                  sizeof(mp_limb_t), /*endian=*/0, /*nails=*/0, S.B.data());

  // Multiply using only mpz_* APIs (Option A).
  gmp.mpz_mul_(Z.c, Z.a, Z.b);

  std::size_t used_limbs = gmp.mpz_size_(Z.c);
  if (used_limbs == 0) used_limbs = 1;
  S.C.assign(used_limbs, 0);

  std::size_t exported = 0;
  gmp.mpz_export_(S.C.data(), &exported, /*order=*/-1, sizeof(mp_limb_t),
                  /*endian=*/0, /*nails=*/0, Z.c);
  if (exported == 0) exported = 1;

  std::vector<Fp> out(n + m - 1, F.Zero());
  unpack_poly_bits(out, S.C.data(), static_cast<mp_size_t>(exported), base_bits,
                   F, PS);
  return out;
}
#endif

}  // namespace detail

std::vector<Fp> MulCoeffsNaiveTrunc(const FpContext& F, const std::vector<Fp>& a,
                                   std::size_t an, const std::vector<Fp>& b,
                                   std::size_t bn, std::size_t out_need) {
  std::vector<Fp> out(out_need, F.Zero());
  for (std::size_t i = 0; i < an; ++i) {
    const Fp ai = a[i];
    if (ai.v == 0) {
      continue;
    }
    const std::size_t jmax = std::min<std::size_t>(bn, out_need - i);
    for (std::size_t j = 0; j < jmax; ++j) {
      const Fp bj = b[j];
      if (bj.v == 0) {
        continue;
      }
      out[i + j] = F.Add(out[i + j], F.Mul(ai, bj));
    }
  }
  return out;
}

std::vector<Fp> MulCoeffsNTTTrunc(const FpContext& F, const std::vector<Fp>& a,
                                 std::size_t an, const std::vector<Fp>& b,
                                 std::size_t bn, std::size_t out_need) {
  const std::size_t min_dim = std::min(an, bn);
  const u64 p = F.GetModulus();

  static constexpr std::size_t kWideCutover =
      4096;  // out_need >= 4096 才切到 64 位 NTT
  const bool wide_ntt = (p > (1ULL << 40)) && (out_need >= kWideCutover);
  const std::size_t prime_count = wide_ntt
                                      ? detail::select_prime_count64(p, min_dim)
                                      : detail::select_prime_count(p, min_dim);

#ifndef NDEBUG
  // Debug guard: ensure CRT product covers coefficient bound.
  const double log2_bound = std::log2(static_cast<double>(min_dim)) +
                            2.0 * std::log2(static_cast<double>(p));
  double log2_M = 0.0;
  if (wide_ntt) {
    for (std::size_t i = 0; i < prime_count; ++i) {
      log2_M += std::log2(static_cast<double>(detail::kNTT64[i].mod));
    }
  } else {
    for (std::size_t i = 0; i < prime_count; ++i) {
      log2_M += std::log2(static_cast<double>(detail::kNTT[i].mod));
    }
  }
  assert(log2_M > log2_bound + 2.0);
#endif

  std::vector<Fp> out(out_need, F.Zero());

  if (wide_ntt) {
    std::vector<std::vector<detail::u64>> residues(prime_count);

    for (std::size_t idxp = 0; idxp < prime_count; ++idxp) {
      const detail::u64 mod = detail::kNTT64[idxp].mod;

      std::vector<detail::u64> A64(an);
      std::vector<detail::u64> B64(bn);
      for (std::size_t i = 0; i < an; ++i) {
        A64[i] = a[i].v % mod;
      }
      for (std::size_t j = 0; j < bn; ++j) {
        B64[j] = b[j].v % mod;
      }

      detail::convolution_mod_ntt64_into(residues[idxp], A64, B64, idxp);
      if (residues[idxp].size() > out_need) {
        residues[idxp].resize(out_need);
      }
    }

    detail::CRT3Plan64 crt_plan(p);
    std::array<detail::u64, 3> r{};

    for (std::size_t i = 0; i < out_need; ++i) {
      for (std::size_t idxp = 0; idxp < 3; ++idxp) {
        r[idxp] = residues[idxp][i];
      }
      const u64 val = crt_plan.combine_to_mod_p(r.data());
      out[i] = Fp{val};
    }
    return out;
  }

  std::vector<std::vector<detail::u32>> residues(prime_count);

  for (std::size_t idxp = 0; idxp < prime_count; ++idxp) {
    const auto prm = detail::kNTT[idxp];

    std::vector<detail::u32> A32(an);
    std::vector<detail::u32> B32(bn);
    // [BARRETT INPUT REDUCE] avoid % in input conversion
    auto& CC = detail::ensure_ntt_cache(idxp, 1U);
    const detail::u32 mod = prm.mod;
    const detail::u64 im = CC.barrett_im;

    for (std::size_t i = 0; i < an; ++i) {
      A32[i] = detail::barrett_reduce_u64(static_cast<detail::u64>(a[i].v), mod,
                                          im);
    }
    for (std::size_t j = 0; j < bn; ++j) {
      B32[j] = detail::barrett_reduce_u64(static_cast<detail::u64>(b[j].v), mod,
                                          im);
    }

    detail::convolution_mod_ntt_into(residues[idxp], A32, B32, idxp);
    if (residues[idxp].size() > out_need) {
      residues[idxp].resize(out_need);
    }
  }

  if (prime_count <= 3) {
    detail::CRT3Plan crt_plan(p);
    std::array<detail::u32, 3> r{};

    for (std::size_t i = 0; i < out_need; ++i) {
      for (std::size_t idxp = 0; idxp < 3; ++idxp) {
        r[idxp] = residues[idxp][i];
      }
      const u64 val = crt_plan.combine_to_mod_p(r.data());
      out[i] = Fp{val};
    }
  } else {
    detail::CRT5Plan crt_plan(p);
    std::array<detail::u32, 5> r{};

    for (std::size_t i = 0; i < out_need; ++i) {
      for (std::size_t idxp = 0; idxp < prime_count; ++idxp) {
        r[idxp] = residues[idxp][i];
      }
      const u64 val = crt_plan.combine_to_mod_p(r.data());
      out[i] = Fp{val};
    }
  }

  return out;
}

std::vector<Fp> MulCoeffsTrunc(const FpContext& F, const std::vector<Fp>& a,
                               const std::vector<Fp>& b, std::size_t k,
                               bool allow_gmp) {
  if (k == 0 || a.empty() || b.empty()) {
    return {};
  }

  const std::size_t an = std::min<std::size_t>(a.size(), k);
  const std::size_t bn = std::min<std::size_t>(b.size(), k);
  if (an == 0 || bn == 0) {
    return {};
  }

  const std::size_t full_need = an + bn - 1;
  const std::size_t out_need = std::min<std::size_t>(k, full_need);
  const std::size_t min_dim = std::min(an, bn);

#ifdef BIGNUM_WITH_GMP
  if (allow_gmp && out_need == full_need && an == a.size() && bn == b.size()) {
    if (::yacl::math::gmp::GMPLoader::Instance().IsLoaded()) {
      return detail::mul_kronecker_coeffs(F, a, b);
    }
  }
#else
  (void)allow_gmp;
#endif

  // 小规模继续用朴素（避免 NTT 常数）
  if (out_need <= 256 || min_dim <= 64) {
    return MulCoeffsNaiveTrunc(F, a, an, b, bn, out_need);
  }

  return MulCoeffsNTTTrunc(F, a, an, b, bn, out_need);
}

}  // namespace

FpPolynomial FpPolynomial::Mul(const FpPolynomial& g) const {
  RequireCompat(g);
  const FpContext& F = *ctx_;

  if (IsZero() || g.IsZero()) {
    return FpPolynomial(F);
  }

  const std::size_t need = c_.size() + g.c_.size() - 1;
  std::vector<Fp> out = MulCoeffsTrunc(F, c_, g.c_, need, /*allow_gmp=*/true);

  FpPolynomial res(F, std::move(out));
  res.Trim();
  return res;
}

FpPolynomial FpPolynomial::MulTruncPoly(const FpPolynomial& a,
                                        const FpPolynomial& b, size_type k) {
  a.RequireCompat(b);
  const FpContext& F = *a.ctx_;

  std::vector<Fp> out = MulCoeffsTrunc(F, a.c_, b.c_, k, /*allow_gmp=*/false);
  FpPolynomial res(F, std::move(out));
  res.Trim();
  return res;
}

}  // namespace yacl::crypto::experimental::poly
