#pragma once

#include <functional>

namespace yasl::utils {

// This is a copy of boost hash_combine
// See
// https://www.boost.org/doc/libs/1_49_0/doc/html/hash/reference.html#boost.hash_combine
template <class T>
inline void hash_combine(std::size_t& seed, const T& v) {
  std::hash<T> hasher;
  seed ^= hasher(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
}

// A helper function to make hashing multiply values easier
template <class T, class... MoreT>
inline void hash_combine(std::size_t& seed, const T& v, const MoreT&... args) {
  hash_combine(seed, v);
  hash_combine(seed, args...);
}

}  // namespace yasl::utils
