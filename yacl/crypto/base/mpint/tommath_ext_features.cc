// Copyright 2022 Ant Group Co., Ltd.
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

#include "yacl/crypto/base/mpint/tommath_ext_features.h"

#include <algorithm>
#include <functional>

#include "tommath_private.h"

#include "yacl/base/buffer.h"
#include "yacl/base/exception.h"
#include "yacl/utils/scope_guard.h"

#ifndef MPINT_ENFORCE_OK
#define MPINT_ENFORCE_OK(MP_ERR, ...) YACL_ENFORCE_EQ((MP_ERR), 0, __VA_ARGS__)
#endif

namespace yacl::crypto {

namespace {
// small_primes is a list of small, prime numbers that allows us to rapidly
// exclude some fraction of composite candidates when searching for a random
// prime. This list is truncated at the point where smal_prime_prod exceeds
// a uint64. It does not include two because we ensure that the candidates are
// odd by construction.
constexpr uint8_t small_primes[] = {3,  5,  7,  11, 13, 17, 19, 23,
                                    29, 31, 37, 41, 43, 47, 53};

template <std::size_t N>
constexpr uint64_t multiply_accumulator(uint8_t const (&A)[N],
                                        std::size_t const i = 0) {
  return (i < N) ? A[i] * multiply_accumulator(A, i + 1) : 1ULL;
}

// small_prime_prod is the product of the values in smallPrimes and allows us
// to reduce a candidate prime by this number and then determine whether it's
// coprime to all the elements of smallPrimes without further big int
// operations.
// NOTE: std::accumulate is only constexpr since C++20.
constexpr uint64_t small_prime_prod = multiply_accumulator(small_primes);

}  // namespace

bool is_co_prime(uint64_t num, const uint8_t small_primes[], int size) {
  for (int i = 0; i < size; i++) {
    if (num != small_primes[i] && num % small_primes[i] == 0) {
      return false;
    }
  }
  return true;
}

inline bool is_prime_candidate(const mp_int *p) {
  uint64_t mod;
  // mod = p % small_prime_prod
  MPINT_ENFORCE_OK(mp_mod_d(p, small_prime_prod, &mod));
  // check co-prime
  return is_co_prime(mod, small_primes, std::size(small_primes));
}

// Pocklington's criterion:
// Let P>1 be an integer, and suppose there exist natural numbers A and Q such
// that
//   * A^{P-1} = 1 mod P
//   * Q is prime, Q|N−1 and Q > sqrt(P) - 1
//   * gcd(A^{(P-1)/Q} - 1, P) = 1
// Then P is prime
//
// Pocklington's criterion can be used to prove the primality of `p = 2q + 1`
// once one has proven the primality of `q`.
// With `q` prime, `p = 2q + 1`, and `p` passing Fermat's primality test to base
// `2` that `2^{p-1} = 1 (mod p)` then `p` is prime as well.
bool is_pocklington_criterion_satisfied(const mp_int *p) {
  mp_int p_minus_one, two, result;

  MPINT_ENFORCE_OK(mp_init(&p_minus_one));
  ON_SCOPE_EXIT([&] { mp_clear(&p_minus_one); });
  MPINT_ENFORCE_OK(mp_init_u64(&two, 2));
  ON_SCOPE_EXIT([&] { mp_clear(&two); });
  MPINT_ENFORCE_OK(mp_init(&result));
  ON_SCOPE_EXIT([&] { mp_clear(&result); });
  // p - 1
  MPINT_ENFORCE_OK(mp_sub_d(p, 1, &p_minus_one));
  // 2^(p-1) mod p
  MPINT_ENFORCE_OK(mp_exptmod(&two, &p_minus_one, p, &result));
  return (mp_cmp_d(&result, 1) == 0);
}

// The algorithm is as follows:
// 1. Generate a random odd number `q` of length `psize-1` with two the most
//    significant bits set to `1`.
// 2. Execute preliminary primality test on `q` checking whether it is coprime
//    to all the elements of `small_primes`. It allows to eliminate trivial
//    cases quickly, when `q` is obviously no prime, without running an
//    expensive final primality tests.
//    If `q` is coprime to all the `smallPrimes`, then go to the point 3.
//    If not, add `2` and try again. Do it at most 10 times.
// 3. Check the potentially prime `q`, whether `q = 1 (mod 3)`. This will
//    happen for 50% of cases.
//    If it is, then `p = 2q+1` will be a multiple of 3, so it will be obviously
//    not a prime number. In this case, add `2` and try again. Do it at most 10
//    times. If `q != 1 (mod 3)`, go to the point 4.
// 4. Now we know `q` is potentially prime and `p = 2q+1` is not a multiple of
//    3. We execute a preliminary primality test on `p`, checking whether
//    it is coprime to all the elements of `small_primes` just like we did for
//    `q` in point 2. If `p` is not coprime to at least one element of the
//    `small_primes`, then go back to point 1.
//    If `p` is coprime to all the elements of `small_primes`, go to point 5.
// 5. At this point, we know `q` is potentially prime, and `p=q+1` is also
//    potentially prime. We need to execute a final primality test for `q`.
//    We apply Miller-Rabin and Baillie-PSW tests. If they succeed, it means
//    that `q` is prime with a very high probability. Knowing `q` is prime,
//    we use Pocklington's criterion to prove the primality of `p=2q+1`, that
//    is, we execute Fermat primality test to base 2 checking whether
//    `2^{p-1} = 1 (mod p)`. It's significantly faster than running full
//    Miller-Rabin and Baillie-PSW for `p`.
//    If `q` and `p` are found to be prime, return them as a result. If not, go
//    back to the point 1.
void mp_ext_safe_prime_rand(mp_int *p, int t, int psize) {
  uint8_t maskAND, maskOR_msb, maskOR_lsb;
  int maskOR_msb_offset;
  mp_bool res;
  mp_int q;
  uint64_t mod;

  /* sanity check the input */
  YACL_ENFORCE(psize > 1 && t > 0, "with psize={}, t={}", psize, t);

  int qsize = psize - 1;
  /* calc the byte size */
  int bsize = (qsize + 7) >> 3;

  /* we need a buffer of bsize bytes */
  yacl::Buffer buf((size_t)bsize);
  uint8_t *tmp = buf.data<uint8_t>();

  MPINT_ENFORCE_OK(mp_init(&q));
  ON_SCOPE_EXIT([&] { mp_clear(&q); });

  /* calc the maskAND value for the MSbyte*/
  maskAND = ((qsize & 7) == 0) ? 0xFFu : (uint8_t)(0xFFu >> (8 - (qsize & 7)));
  /* calc the maskOR_msb */
  maskOR_msb = 0;
  maskOR_msb_offset = ((qsize & 7) == 1) ? 1 : 0;
  // second msb
  maskOR_msb |= (uint8_t)(0x80 >> ((9 - qsize) & 7));
  // 3 mod 4
  maskOR_lsb = 1u;
  maskOR_lsb |= 3u;

  do {
    /* read the bytes */
    MPINT_ENFORCE_OK(s_mp_rand_source(tmp, (size_t)bsize));

    // clear bits in the first byte
    tmp[0] &= maskAND;
    // set the MSB to 1
    tmp[0] |= (uint8_t)(1 << ((qsize - 1) & 7));
    // set the second MSB to 1
    tmp[maskOR_msb_offset] |= maskOR_msb;
    // 3 mod 4
    tmp[bsize - 1] |= maskOR_lsb;

    /* read it in */
    /* TODO: casting only for now until all lengths have been changed to the
     * type "size_t"*/
    MPINT_ENFORCE_OK(mp_from_ubin(&q, tmp, (size_t)bsize));

    // Find a odd number `q` among q, q+2, .... , (1 << 20) satisfy：
    // 1. co-prime to `small_primes`.
    // 2. `q = 1 mod 3` (p = 2q+1).
    MPINT_ENFORCE_OK(mp_mod_d(&q, small_prime_prod, &mod));

    uint64_t last_delta = 0;
    for (uint64_t delta = 0; delta < (1 << 20); delta += 2) {
      uint64_t m = mod + delta;
      if (!is_co_prime(m, small_primes, std::size(small_primes))) {
        continue;
      }
      if (delta - last_delta > 0) {
        MPINT_ENFORCE_OK(mp_add_d(&q, delta - last_delta, &q));
      }
      last_delta = delta;
      // If `q = 1 (mod 3)`, then `p` is a multiple of `3` so it's
      // obviously no prime and such `p` should be rejected.
      MPINT_ENFORCE_OK(mp_mod_d(&q, 3, &mod));
      if (mod == 1) {
        continue;
      }
      // p = 2 * q + 1
      MPINT_ENFORCE_OK(mp_mul_2(&q, p));
      MPINT_ENFORCE_OK(mp_incr(p));

      if (mp_ext_count_bits_fast(*p) != psize) {
        continue;
      }
      if (is_prime_candidate(p)) {
        break;
      }
    }
    // is `q` a prime? try 10 times.
    MPINT_ENFORCE_OK(mp_prime_is_prime(&q, 10, &res));
    if (!res) {
      continue;
    }
    // test Pocklington Criterion
    if (!is_pocklington_criterion_satisfied(&q)) {
      continue;
    }
    // final check
    MPINT_ENFORCE_OK(mp_prime_is_prime(&q, t, &res));
    if (!res) {
      continue;
    }
    MPINT_ENFORCE_OK(mp_prime_is_prime(p, t, &res));
  } while (!res);
}

void mp_ext_rand_bits(mp_int *out, int64_t bits) {
  if (bits <= 0) {
    mp_zero(out);
    return;
  }

  int digits = static_cast<int>((bits + MP_DIGIT_BIT - 1) / MP_DIGIT_BIT);
  MPINT_ENFORCE_OK(mp_grow(out, digits));

  MPINT_ENFORCE_OK(
      s_mp_rand_source(out->dp, (size_t)digits * sizeof(mp_digit)));

  out->sign = MP_ZPOS;
  out->used = digits;
  for (int i = 0; i < digits; ++i) {
    out->dp[i] &= MP_MASK;
  }

  int64_t remain_bits = bits % MP_DIGIT_BIT;
  if (remain_bits > 0) {
    out->dp[digits - 1] &= (((mp_digit)1 << remain_bits) - 1);
  }

  for (int i = digits; i < out->alloc; ++i) {
    out->dp[i] = 0;
  }
  mp_clamp(out);
}

// "De Bruijn" Algorithm
// Original paper: http://supertech.csail.mit.edu/papers/debruijn.pdf
// However, the original "De Bruijn" Algorithm only works with uint32_t
// This 64-bits version borrows from:
// https://stackoverflow.com/questions/21888140/de-bruijn-algorithm-binary-digit-count-64bits-c-sharp
//
// Note: "De Bruijn" is the fastest portable algorithms.
// Other ways such as std:__lg(), __builtin_clz or _BitScanReverse are not
// portable
// Note2: The POSIX function 'ffs' not meet requirements.
//   https://man7.org/linux/man-pages/man3/ffsll.3.html
int count_bits_debruijn(uint64_t v) {
  static const int bitPatternToLog2[128] = {
      0,  48, -1, -1, 31, -1, 15, 51, -1, 63, 5,  -1, -1, -1, 19, -1,
      23, 28, -1, -1, -1, 40, 36, 46, -1, 13, -1, -1, -1, 34, -1, 58,
      -1, 60, 2,  43, 55, -1, -1, -1, 50, 62, 4,  -1, 18, 27, -1, 39,
      45, -1, -1, 33, 57, -1, 1,  54, -1, 49, -1, 17, -1, -1, 32, -1,
      53, -1, 16, -1, -1, 52, -1, -1, -1, 64, 6,  7,  8,  -1, 9,  -1,
      -1, -1, 20, 10, -1, -1, 24, -1, 29, -1, -1, 21, -1, 11, -1, -1,
      41, -1, 25, 37, -1, 47, -1, 30, 14, -1, -1, -1, -1, 22, -1, -1,
      35, 12, -1, -1, -1, 59, 42, -1, -1, 61, 3,  26, 38, 44, -1, 56};

  v |= v >> 1;
  v |= v >> 2;
  v |= v >> 4;
  v |= v >> 8;
  v |= v >> 16;
  v |= v >> 32;
  return bitPatternToLog2[(v * 0x6c04f118e9966f6bULL) >> 57];
}

int mp_ext_count_bits_fast(const mp_int &a) {
  if (a.used == 0) {
    return 0;
  }

  return (a.used - 1) * MP_DIGIT_BIT + count_bits_debruijn(a.dp[a.used - 1]);
}

void mp_ext_to_bytes(const mp_int &num, unsigned char *buf, int64_t byte_len,
                     Endian endian) {
  YACL_ENFORCE(MP_DIGIT_BIT % 4 == 0, "Unsupported MP_DIGIT_BIT {}",
               MP_DIGIT_BIT);

  int64_t pos = 0;
  mp_digit ac = 1;
  mp_digit cache = 0;
  int cache_remain = 0;

  for (int digit_idx = 0; pos < byte_len; digit_idx++) {
    mp_digit x;

    // convert to complement
    if (num.sign == MP_NEG) {
      ac += (digit_idx >= num.used) ? MP_MASK : (~num.dp[digit_idx] & MP_MASK);
      x = ac & MP_MASK;
      ac >>= MP_DIGIT_BIT;
    } else {
      x = (digit_idx >= num.used) ? 0uL : num.dp[digit_idx];
    }

    // convert complement to bytes
    cache |= x << cache_remain;
    cache_remain += MP_DIGIT_BIT;
    for (; cache_remain >= 8 && pos < byte_len; cache_remain -= 8) {
      if (endian == Endian::little) {
        buf[pos] = cache & 255;
      } else {
        buf[byte_len - 1 - pos] = cache & 255;
      }
      cache >>= 8;
      pos++;
    }

    // process residual cache
    if (cache > 0 && pos < byte_len) {
      if (endian == Endian::little) {
        buf[pos] = cache & 255;
      } else {
        buf[byte_len - 1 - pos] = cache & 255;
      }
    }
  }
}

size_t mp_ext_serialize_size(const mp_int &num) {
  auto bits = mp_ext_count_bits_fast(num);
  return (bits + 7) / 8 + 1;  // we add an extra meta byte
}

void mp_ext_serialize(const mp_int &num, uint8_t *buf, size_t buf_len) {
  YACL_ENFORCE(MP_DIGIT_BIT % 4 == 0, "Unsupported MP_DIGIT_BIT {}",
               MP_DIGIT_BIT);
  YACL_ENFORCE_GE(buf_len, mp_ext_serialize_size(num),
                  "buf is too small to serialize mp_int");

  // buf[0] is meta byte
  if (mp_isneg(&num)) {
    buf[0] = 1;
  } else {
    buf[0] = 0;
  }

  if (num.used == 0) {
    return;
  }

  int64_t pos = 1;
  mp_digit cache = 0;
  int cache_remain = 0;
  // store num in Little-Endian
  for (int digit_idx = 0; digit_idx < num.used - 1; ++digit_idx) {
    // process next mp_digit
    cache |= num.dp[digit_idx] << cache_remain;
    cache_remain += MP_DIGIT_BIT;

    for (; cache_remain >= 8; cache_remain -= 8) {
      buf[pos++] = cache & 255;
      cache >>= 8;
    }
  }

  // process last digit
  cache |= num.dp[num.used - 1] << cache_remain;
  while (cache > 0) {
    buf[pos++] = cache & 255;
    cache >>= 8;
  }
}

void mp_ext_deserialize(mp_int *num, const uint8_t *buf, size_t buf_len) {
  YACL_ENFORCE(buf_len > 0, "mp_int deserialize: empty buffer");

  /* make sure there are at least two digits */
  int total_digits =
      ((buf_len - 1) * CHAR_BIT + MP_DIGIT_BIT - 1) / MP_DIGIT_BIT;
  if (num->alloc < total_digits) {
    MPINT_ENFORCE_OK(mp_grow(num, total_digits));
  }

  num->sign = buf[0] == 0 ? MP_ZPOS : MP_NEG;
  num->used = 0;
  mp_digit cache = 0;
  int cache_bits = 0;
  for (size_t buf_idx = 1; buf_idx < buf_len; ++buf_idx) {
    cache |= (static_cast<mp_digit>(buf[buf_idx]) << cache_bits);
    cache_bits += 8;

    if (cache_bits >= MP_DIGIT_BIT) {
      num->dp[num->used++] = cache & MP_MASK;
      cache >>= MP_DIGIT_BIT;
      cache_bits -= MP_DIGIT_BIT;
    }
  }
  if (cache > 0) {
    num->dp[num->used++] = cache & MP_MASK;
  }
}

uint8_t mp_ext_get_bit(const mp_int &a, int index) {
  int limb = index / MP_DIGIT_BIT;
  if (limb >= a.used) {
    return 0;
  }

  return (a.dp[limb] >> (index % MP_DIGIT_BIT)) & 1;
}

void mp_ext_set_bit(mp_int *a, int index, uint8_t value) {
  int limb = index / MP_DIGIT_BIT;
  if (limb > a->alloc) {
    MPINT_ENFORCE_OK(mp_grow(a, limb + 1));
    for (int i = a->used + 1; i <= limb; ++i) {
      a->dp[i] = 0;
    }
  }

  if (limb >= a->used) {
    a->used = limb + 1;
  }

  mp_digit loc = static_cast<mp_digit>(1) << (index % MP_DIGIT_BIT);
  value != 0 ? a->dp[limb] |= loc : a->dp[limb] &= ~loc;
  mp_clamp(a);
}

}  // namespace yacl::crypto
