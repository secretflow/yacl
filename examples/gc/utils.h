#include <bits/stdc++.h>
#include <emmintrin.h>
#include <openssl/sha.h>

#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <random>

using uint128_t = __uint128_t;
using block = uint128_t;

template <typename T>
inline void int_to_bool(bool* data, T input, int len);

inline uint128_t make_uint128_t(uint64_t high, uint64_t low) {
  return (static_cast<uint128_t>(high) << 64) | low;
}

void random_uint128_t(uint128_t* data, int nblocks = 1);

template <typename T>
inline void int_to_bool(bool* data, T input, int len) {
  for (int i = 0; i < len; ++i) {
    data[i] = (input & 1) == 1;
    input >>= 1;
  }
}

// get the Least Significant Bit of uint128_t
inline bool getLSB(const uint128_t& x) { return (x & 1) == 1; }
