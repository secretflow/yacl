#pragma once

#include <random>

#include "yasl/base/int128.h"

namespace yasl {

inline uint128_t RandSeed() {
  // call random_device four times, make sure uint128 is random in 2^128 set.
  std::random_device rd;
  uint64_t lhs = static_cast<uint64_t>(rd()) << 32 | rd();
  uint64_t rhs = static_cast<uint64_t>(rd()) << 32 | rd();
  return yasl::MakeUint128(lhs, rhs);
}

}  // namespace yasl