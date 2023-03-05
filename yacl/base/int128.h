// Copyright 2019 Ant Group Co., Ltd.
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

#include <iostream>
#include <limits>

// NOTE:
// We add our own int128 due to:
// - absl::int128 forget to support fully `constexpr`, i.e. `operator>>`. Giving
//   a patch for this will be a bit heavy.
// - absl::int128 incorrectly instantiated std::numeric_limits<__int128>::traps,
//   solved by trivial patch, easy to maintain.

// Always require the compiler to support intrinsic 128 bits.
using int128_t = __int128;
using uint128_t = unsigned __int128;

namespace yacl {
namespace details {

// from abseil.
constexpr __int128 BitCastToSigned(unsigned __int128 v) {
  // Casting an unsigned integer to a signed integer of the same
  // width is an implementation-defined behavior if the source value would not fit
  // in the destination type. We step around it with a roundtrip bitwise-not
  // operation to make sure this function remains constexpr. Clang and GCC
  // optimize this to a no-op on x86-64.
  return v & (static_cast<unsigned __int128>(1) << 127)
             ? ~static_cast<__int128>(~v)
             : static_cast<__int128>(v);
}

}  // namespace details

inline constexpr int128_t MakeInt128(int64_t hi, uint64_t lo) {
  return details::BitCastToSigned(static_cast<unsigned __int128>(hi) << 64) |
         lo;
}

inline constexpr uint128_t MakeUint128(uint64_t hi, uint64_t lo) {
  return static_cast<uint128_t>(hi) << 64 | lo;
}

inline constexpr int128_t Int128Max() {
  return MakeInt128(std::numeric_limits<int64_t>::max(),
                    std::numeric_limits<uint64_t>::max());
}

inline constexpr int128_t Int128Min() {
  return MakeInt128(std::numeric_limits<int64_t>::min(), 0);
}

inline constexpr uint128_t Uint128Max() {
  return MakeUint128(std::numeric_limits<uint64_t>::max(),
                     std::numeric_limits<uint64_t>::max());
}

inline constexpr uint128_t Uint128Min() { return 0; }

std::pair<int64_t, uint64_t> DecomposeInt128(int128_t v);

std::pair<uint64_t, uint64_t> DecomposeUInt128(uint128_t v);

}  // namespace yacl

#ifdef __GNUC__
#define HAS_INT128_LIMITS
#if defined(__clang__) || \
    (defined(__GLIBCXX_TYPE_INT_N_0) && (__GLIBCXX_TYPE_INT_N_0 == __int128))
#define HAS_INT128_TRAITS
#endif
#else
#error "YACL only supports GCC and clang"
#endif

namespace std {

constexpr int128_t abs(int128_t x) { return x >= 0 ? x : -x; }

constexpr int128_t abs(uint128_t x) { return x; }

// double log10(int128_t x) { return std::log10(static_cast<double>(x)); }

std::ostream& operator<<(std::ostream& os, int128_t x);
std::ostream& operator<<(std::ostream& os, uint128_t x);

#if __GNUC__ >= 10
constexpr double log10(int128_t x) {
  return std::log10(static_cast<double>(x));
}

constexpr double log10(uint128_t x) { return 0.0; }
#endif

#ifndef HAS_INT128_TRAITS
template <>
struct is_scalar<uint128_t> : public true_type {};

template <>
struct is_scalar<int128_t> : public true_type {};

template <>
struct is_integral<uint128_t> : public true_type {};

template <>
struct is_integral<int128_t> : public true_type {};

template <>
struct is_arithmetic<int128_t> : public true_type {};

template <>
struct is_arithmetic<uint128_t> : public true_type {};
#endif

template <>
struct make_unsigned<int128_t> {
  using type = uint128_t;
};

template <>
struct make_unsigned<uint128_t> {
  using type = uint128_t;
};

template <>
struct make_signed<uint128_t> {
  using type = int128_t;
};

template <>
struct make_signed<int128_t> {
  using type = int128_t;
};

}  // namespace std
