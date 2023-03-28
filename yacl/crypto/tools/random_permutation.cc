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
}

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

// uint128_t CcrHash_128(uint128_t x) {
//   return CrHash_128(x ^ (x >> 64 & 0xffffffffffffffff));
// }

// std::vector<uint128_t> ParaCrrHash_128(absl::Span<const uint128_t> x) {}

// void ParaCcrHash_128(absl::Span<const uint128_t> x, absl::Span<uint128_t>
// out) {
//   std::vector<uint128_t> tmp(x.size());
//   for (size_t i = 0; i < x.size(); i++) {
//     tmp[i] = x[i] ^ (x[i] >> 64 & 0xffffffffffffffff);
//   }
// }

}  // namespace yacl::crypto
