// Copyright 2023 Ant Group Co., Ltd.
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

#include "yacl/crypto/tools/rp.h"

#include <algorithm>
#include <cstdint>

namespace yacl::crypto {

using Ctype = SymmetricCrypto::CryptoType;

void RP::Gen(absl::Span<const uint128_t> x, absl::Span<uint128_t> out) const {
  YACL_ENFORCE(x.size() == out.size());
  sym_alg_.Encrypt(x, out);
}

std::vector<uint128_t> RP::Gen(absl::Span<const uint128_t> x) const {
  std::vector<uint128_t> res(x.size());
  Gen(x, absl::MakeSpan(res));
  return res;
}

void RP::GenInplace(absl::Span<uint128_t> inout) const {
  sym_alg_.Encrypt(inout, inout);
}

uint128_t RP::Gen(uint128_t x) const {
  YACL_ENFORCE(sym_alg_.GetType() != Ctype::AES128_CTR);
  return sym_alg_.Encrypt(x);
}

}  // namespace yacl::crypto
