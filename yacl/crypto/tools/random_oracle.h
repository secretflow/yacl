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

#include "yacl/crypto/base/symmetric_crypto.h"

namespace yacl {

// Symmetric crypto based random oracle.
//
class RandomOracle {
 public:
  explicit RandomOracle(SymmetricCrypto::CryptoType ctype, uint128_t key,
                        uint128_t iv = 0)
      : sym_alg(ctype, key, iv) {}

  // Flat output.
  template <size_t N = 1>
  auto Gen(uint128_t x) const {
    if constexpr (N == 1) {
      uint128_t output;
      Gen(x, absl::Span<uint128_t>(&output, 1));
      return output;
    } else {
      std::array<uint128_t, N> output;
      Gen(x, absl::MakeSpan(output));
      return output;
    }
  }

  // Overload for dynamic containers say `vector<uint128_t>`.
  void Gen(uint128_t x, absl::Span<uint128_t> out) const {
    std::vector<uint128_t> input(out.size(), 0);
    for (size_t i = 0; i < out.size(); ++i) {
      input[i] = x + i;
    }
    sym_alg.Encrypt(input, out);
  }

  static RandomOracle& GetDefault() {
    constexpr uint128_t kDefaultRoAesKey = 0x12345678;
    static RandomOracle ro(SymmetricCrypto::CryptoType::AES128_ECB,
                           kDefaultRoAesKey);
    return ro;
  }

 private:
  SymmetricCrypto sym_alg;
};

}  // namespace yacl
