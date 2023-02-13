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

#include <functional>

namespace yacl::utils {

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

}  // namespace yacl::utils
