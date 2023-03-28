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
#include "yacl/crypto/base/aes/aes_intrinsics.h"
#include "yacl/crypto/base/symmetric_crypto.h"

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
class RandomPerm {
 public:
  using Ctype = SymmetricCrypto::CryptoType;

  explicit RandomPerm(Ctype ctype, uint128_t key, uint128_t iv = 0)
      : sym_alg_(ctype, key, iv) {}

  // generate a block x's random permutation, and outputs
  uint128_t Gen(uint128_t x) const;

  // given input block vector x, generate its random permutation.
  std::vector<uint128_t> Gen(absl::Span<const uint128_t> x) const;

  // given input block vector x, generate its random permutation to out.
  void Gen(absl::Span<const uint128_t> x, absl::Span<uint128_t> out) const;

  // generate (block vector) x's random permutation, and inplace
  void GenInplace(absl::Span<uint128_t> inout);

  // Example: const auto rp = RandomPerm::GetDefault();
  static RandomPerm& GetDefault() {
    // Note: it's ok to use AES CTR blocks when you want to encrypt multiple
    // blocks, but when you want to encrypt a single block, please use ECB or
    // CBC
    static RandomPerm rp(Ctype::AES128_CBC, 0x12345678);
    return rp;
  }

 private:
  SymmetricCrypto sym_alg_;
  // AES_KEY aes_key_;
};

// Correlation Robust Hash function (Single Block input)
// See https://eprint.iacr.org/2019/074.pdf Sec 7.2
// CrHash = RP(x) ^ x
uint128_t CrHash_128(uint128_t x);

// parallel crhash for many blocks
std::vector<uint128_t> ParaCrHash_128(absl::Span<const uint128_t> x);

// inplace parallel crhash for many blocks
void ParaCrHashInplace_128(absl::Span<uint128_t> inout);

// Circular Correlation Robust Hash function (Single Block)
// See https://eprint.iacr.org/2019/074.pdf Sec 7.3
// CcrHash = RP(theta(x)) ^ theta(x)
// theta(x) = x ^ ((x.left ^ x.right) >> 64)
// uint128_t CcrHash_128(uint128_t x);

// std::vector<uint128_t> ParaCrrHash_128(absl::Span<const uint128_t> x);

// Evaluate many CrHash in Parallel (Single Block input)
// inline void ParaCcrHash_128(absl::Span<const uint128_t> x,
//                             absl::Span<uint128_t> out) {
//   std::vector<uint128_t> tmp(x.size());
//   for (size_t i = 0; i < x.size(); i++) {
//     tmp[i] = x[i] ^ (x[i] >> 64 & 0xffffffffffffffff);
//   }
// }

// inline std::vector<uint128_t> ParaCcrHash_128(absl::Span<const uint128_t> x)
// {
//   std::vector<uint128_t> res(x.size());
//   ParaCcrHash_128(x, absl::MakeSpan(res));
//   return res;
// }

// TODO(@shanzhu) Tweakable Correlation Robust Hash function (Multiple Blocks)
// See https://eprint.iacr.org/2019/074.pdf Sec 7.4

}  // namespace yacl::crypto
