#include "absl/numeric/bits.h"
#include "absl/types/span.h"

#include "yasl/base/exception.h"
#include "yasl/base/int128.h"

namespace yasl {

// Reference: https://en.wikipedia.org/wiki/Hamming_weight
template <typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
inline constexpr size_t HammingWeight(T i) {
  if constexpr (sizeof(T) == 16) {
    // 128 bits
    auto low64 = static_cast<uint64_t>(i & ~uint64_t{0});
    auto high64 = static_cast<uint64_t>(i >> 64);
    return HammingWeight(low64) + HammingWeight(high64);
  } else {
    // TODO(shuyan.ycf): use `std::popcount` when we switch to c++20.
    return absl::popcount(i);
  }
}

template <typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
inline constexpr size_t HammingDistance(T x, T y) {
  return HammingWeight(x ^ y);
}

}  // namespace yasl
