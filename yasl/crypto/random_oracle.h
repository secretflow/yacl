#pragma once

#include <array>

#include "yasl/crypto/symmetric_crypto.h"

namespace yasl {

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

}  // namespace yasl
