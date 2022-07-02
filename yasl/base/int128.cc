#include "yasl/base/int128.h"

// For importing ostream implementation.
#include "absl/numeric/int128.h"

namespace std {

std::ostream& operator<<(std::ostream& os, int128_t x) {
  return os << static_cast<absl::int128>(x);
}

std::ostream& operator<<(std::ostream& os, uint128_t x) {
  return os << static_cast<absl::uint128>(x);
}

}  // namespace std

namespace yasl {

std::pair<int64_t, uint64_t> DecomposeInt128(int128_t v) {
  auto absl_v = static_cast<absl::int128>(v);
  return {absl::Int128High64(absl_v), absl::Int128Low64(absl_v)};
}

std::pair<uint64_t, uint64_t> DecomposeUInt128(uint128_t v) {
  auto absl_v = static_cast<absl::uint128>(v);
  return {absl::Uint128High64(absl_v), absl::Uint128Low64(absl_v)};
}

}  // namespace yasl