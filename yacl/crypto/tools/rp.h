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

#include <algorithm>
#include <array>
#include <vector>

#include "yacl/base/exception.h"
#include "yacl/base/int128.h"

/* submodules */
// #include "yacl/crypto/aes/aes_intrinsics.h"
#include "yacl/crypto/block_cipher/symmetric_crypto.h"

namespace yacl::crypto {

// This is an implementation of the **theoretical tool**: Random Permutation.
//
// Theoretically, Random Permutation is used to model ideal block ciphers, in
// reality, we use "pseudo-random permutations", for more detailed definition
// and constructions, see:
// - https://omereingold.files.wordpress.com/2014/10/lr.pdf
// - https://crypto.stanford.edu/pbc/notes/crypto/prp.html
// - https://crypto.stackexchange.com/questions/3867
//
// In practice, both AES and DES are Pseudorandom Permutations, we implement
// Random Permutation using AES.
//
// [Security Assumption]: AES with a "fixed-and-public-known" key is a random
// permutation
//
class RP {
 public:
  using Ctype = SymmetricCrypto::CryptoType;

  explicit RP(Ctype ctype, uint128_t key, uint128_t iv = 0)
      : sym_alg_(ctype, key, iv) {}

  // generate a block x's random permutation, and outputs
  uint128_t Gen(uint128_t x) const;

  // given input block vector x, generate its random permutation.
  std::vector<uint128_t> Gen(absl::Span<const uint128_t> x) const;

  // given input block vector x, generate its random permutation to out.
  void Gen(absl::Span<const uint128_t> x, absl::Span<uint128_t> out) const;

  // generate (block vector) x's random permutation, and inplace
  void GenInplace(absl::Span<uint128_t> inout) const;

  // Example: const auto rp = RP::GetDefault();
  static RP& GetDefault() {
    // Note: it's ok to use AES CTR blocks when you want to encrypt multiple
    // blocks, but when you want to encrypt a single block, please use ECB or
    // CBC
    static RP rp(Ctype::AES128_CBC, 0x12345678);
    return rp;
  }

  static const RP& GetCrDefault() {
    static const RP rp(Ctype::AES128_ECB, 0x12345678);
    return rp;
  }

 private:
  SymmetricCrypto sym_alg_;
};

}  // namespace yacl::crypto
