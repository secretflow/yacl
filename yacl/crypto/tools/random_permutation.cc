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

#include "yacl/crypto/tools/random_permutation.h"

#include "yacl/crypto/base/symmetric_crypto.h"

namespace yacl::crypto {

namespace {
using Ctype = SymmetricCrypto::CryptoType;

// Circular Correlation Robust Hash function (Single Block)
// See https://eprint.iacr.org/2019/074.pdf Sec 7.3
// CcrHash = RP(Sigma(x)) ^ Sigma(x)
// Sigma(x) = (x.left ^ x.right) || x.left
inline uint128_t Sigma(uint128_t x) {
  // TODO: Sigma(x) = _mm_shuffle_epi32(a, 78) ^ and_si128(x, mask)
  //       where mask = 1^64 || 0^64
  const auto& [left, right] = DecomposeUInt128(x);
  return MakeUint128(left ^ right, left);
}

// x = SigmaInv( Sigma(x) )
// inline uint128_t SigmaInv(uint128_t x) {
//   auto [left, right] = DecomposeUInt128(x);
//   return MakeUint128(right, left ^ right);
// }
}  // namespace

void RandomPerm::Gen(absl::Span<const uint128_t> x,
                     absl::Span<uint128_t> out) const {
  YACL_ENFORCE(x.size() == out.size());
  sym_alg_.Encrypt(x, out);
}

std::vector<uint128_t> RandomPerm::Gen(absl::Span<const uint128_t> x) const {
  std::vector<uint128_t> res(x.size());
  Gen(x, absl::MakeSpan(res));
  return res;
}

void RandomPerm::GenInplace(absl::Span<uint128_t> inout) {
  sym_alg_.Encrypt(inout, inout);
}

uint128_t RandomPerm::Gen(uint128_t x) const {
  YACL_ENFORCE(sym_alg_.GetType() != Ctype::AES128_CTR);
  return sym_alg_.Encrypt(x);
}

uint128_t CrHash_128(uint128_t x) {
  const auto& RP = RandomPerm::GetDefault();
  return RP.Gen(x) ^ x;
}

std::vector<uint128_t> ParaCrHash_128(absl::Span<const uint128_t> x) {
  std::vector<uint128_t> out(x.size());
  const auto& RP = RandomPerm(Ctype::AES128_ECB, 0x12345678);
  RP.Gen(x, absl::MakeSpan(out));
  for (uint64_t i = 0; i < x.size(); ++i) {
    out[i] ^= x[i];
  }
  return out;
}

void ParaCrHashInplace_128(absl::Span<uint128_t> inout) {
  std::vector<uint128_t> tmp(inout.size());
  const auto& RP = RandomPerm(Ctype::AES128_ECB, 0x12345678);
  RP.Gen(inout, absl::MakeSpan(tmp));
  for (uint64_t i = 0; i < inout.size(); ++i) {
    inout[i] ^= tmp[i];
  }
}

uint128_t CcrHash_128(uint128_t x) { return CrHash_128(Sigma(x)); }

std::vector<uint128_t> ParaCcrHash_128(absl::Span<const uint128_t> x) {
  std::vector<uint128_t> tmp(x.size());
  for (uint64_t i = 0; i < x.size(); ++i) {
    tmp[i] = Sigma(x[i]);
  }
  ParaCrHashInplace_128(absl::MakeSpan(tmp));
  return tmp;
}

void ParaCcrHashInplace_128(absl::Span<uint128_t> inout) {
  for (auto& e : inout) {
    e = Sigma(e);
  }
  ParaCrHashInplace_128(inout);
}

}  // namespace yacl::crypto
