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

#include "yacl/crypto/block_cipher/block_cipher.h"

namespace yacl::crypto {

void RP::Gen(uint128_t in, uint128_t* out) const {
  *out = BlockCipher(ctype_, key_, iv_).Encrypt(in);
}

uint128_t RP::Gen(uint128_t in) const {
  uint128_t out = 0;
  Gen(in, &out);
  return out;
}

void RP::GenForMultiInputs(absl::Span<const uint128_t> in,
                           absl::Span<uint128_t> out) const {
  YACL_ENFORCE(in.size() == out.size());
  BlockCipher(ctype_, key_, iv_).Encrypt(in, out);
}

std::vector<uint128_t> RP::GenForMultiInputs(
    absl::Span<const uint128_t> in) const {
  std::vector<uint128_t> out(in.size());
  GenForMultiInputs(in, absl::MakeSpan(out));
  return out;
}

void RP::GenForMultiInputsInplace(absl::Span<uint128_t> inout) const {
  BlockCipher(ctype_, key_, iv_).Encrypt(inout, inout);
}

}  // namespace yacl::crypto
