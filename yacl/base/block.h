// Copyright 2022 Ant Group Co., Ltd.
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
#include <cstring>
#include <iomanip>
#include <iostream>
#include <type_traits>

#include "absl/types/span.h"

#include "yacl/base/int128.h"

#ifndef __aarch64__
// sse
#include <emmintrin.h>
#include <smmintrin.h>
// pclmul
#include <wmmintrin.h>
#else
#include "sse2neon.h"
#endif

// block code from
// https://github.com/ladnir/cryptoTools/blob/master/cryptoTools/Common/block.h
//
// cryptoTools Licese:
// This project is dual licensed under MIT and Unlicensed.
// For Unlicensed, this project has been placed in the public domain. As such,
// you are unrestricted in how you use it, commercial or otherwise. However, no
// warranty of fitness is provided. If you found this project helpful, feel free
// to spread the word and cite us.

namespace yacl {

struct alignas(16) block {
  __m128i mData;

  block() = default;
  block(const block&) = default;
  block(uint64_t x1, uint64_t x0) { mData = _mm_set_epi64x(x1, x0); }

  block(const uint128_t& x) { mData = (__m128i)x; }

  block& operator=(const block&) = default;

  // operator const uint128_t&() const { return (uint128_t)mData; }
  // operator uint128_t&() { return (uint128_t)mData; }

  block(const __m128i& x) { mData = x; }

  operator const __m128i&() const { return mData; }
  operator __m128i&() { return mData; }

  __m128i& m128i() { return mData; }
  const __m128i& m128i() const { return mData; }
  inline block operator^(const block& rhs) const {
    return _mm_xor_si128(*this, rhs);
  }

  inline block operator+(const block& rhs) const {
    return _mm_add_epi64(*this, rhs);
  }
  inline block operator&(const block& rhs) const {
    return _mm_and_si128(*this, rhs);
  }
  inline block operator|(const block& rhs) const {
    return _mm_or_si128(*this, rhs);
  }
  inline block operator<<(const std::uint8_t& rhs) const {
    return _mm_slli_epi64(*this, rhs);
  }
  inline block operator>>(const std::uint8_t& rhs) const {
    return _mm_srli_epi64(*this, rhs);
  }

  inline bool operator==(const block& rhs) const {
    auto& x = as<std::uint64_t>();
    auto& y = rhs.as<std::uint64_t>();
    return x[0] == y[0] && x[1] == y[1];
  }
  inline bool operator!=(const block& rhs) const {
    auto& x = as<std::uint64_t>();
    auto& y = rhs.as<std::uint64_t>();
    return x[0] != y[0] || x[1] != y[1];
  }

  inline int movemask_epi8() const { return _mm_movemask_epi8(*this); }

  template <typename T>
  typename std::enable_if<std::is_trivially_copyable_v<T> &&
                              (sizeof(T) <= 16) && (16 % sizeof(T) == 0),
                          std::array<T, 16 / sizeof(T)>&>::type
  as() {
    return *(std::array<T, 16 / sizeof(T)>*)this;
  }

  template <typename T>
  typename std::enable_if<std::is_trivially_copyable_v<T> &&
                              (sizeof(T) <= 16) && (16 % sizeof(T) == 0),
                          const std::array<T, 16 / sizeof(T)>&>::type
  as() const {
    return *(const std::array<T, 16 / sizeof(T)>*)this;
  }

  inline bool operator<(const block& rhs) {
    auto& x = as<std::uint64_t>();
    auto& y = rhs.as<std::uint64_t>();
    return x[1] < y[1] || (x[1] == y[1] && x[0] < y[0]);
  }
};

inline block toBlock(std::uint64_t high_uint64, std::uint64_t low_uint64) {
  block ret;
  ret.as<std::uint64_t>()[0] = low_uint64;
  ret.as<std::uint64_t>()[1] = high_uint64;
  return ret;
}
inline block toBlock(std::uint64_t low_uint64) {
  return toBlock(0, low_uint64);
}
inline block toBlock(const std::uint8_t* data) {
  return toBlock(((std::uint64_t*)data)[1], ((std::uint64_t*)data)[0]);
}

inline uint128_t toU128(block data) { return data.as<uint128_t>()[0]; }

}  // namespace yacl
