// Copyright 2019 Ant Group Co., Ltd.
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

#include "yacl/crypto/tools/prg.h"

namespace yacl::crypto {

uint64_t FillPRand(SymmetricCrypto::CryptoType type, uint128_t seed,
                   uint64_t iv, uint64_t count, char* buf, size_t len) {
  constexpr size_t block_size = SymmetricCrypto::BlockSize();
  const size_t nbytes = len;
  const size_t nblock = (nbytes + block_size - 1) / block_size;
  const size_t padding_bytes = nbytes % block_size;

  bool isCTR = (type == SymmetricCrypto::CryptoType::AES128_CTR ||
                type == SymmetricCrypto::CryptoType::SM4_CTR);

  std::unique_ptr<SymmetricCrypto> crypto;
  if (isCTR) {
    // CTR mode does not requires padding or manully build counter...
    crypto = std::make_unique<SymmetricCrypto>(type, seed, count);
    std::memset(buf, 0, nbytes);
    auto bv = absl::MakeSpan(reinterpret_cast<uint8_t*>(buf), nbytes);
    crypto->Encrypt(bv, bv);
  } else {
    crypto = std::make_unique<SymmetricCrypto>(type, seed, iv);
    if (padding_bytes == 0) {
      // No padding, fast path
      auto s = absl::MakeSpan(reinterpret_cast<uint128_t*>(buf), nblock);
      internal::EcbMakeContentBlocks(count, s);
      crypto->Encrypt(s, s);
    } else {
      if (type == SymmetricCrypto::CryptoType::AES128_ECB ||
          type == SymmetricCrypto::CryptoType::SM4_ECB) {
        if (nblock > 1) {
          // first n-1 block
          auto s =
              absl::MakeSpan(reinterpret_cast<uint128_t*>(buf), nblock - 1);
          internal::EcbMakeContentBlocks(count, s);
          crypto->Encrypt(s, s);
        }
        // last padding block
        uint128_t padding = count + nblock - 1;
        padding = crypto->Encrypt(padding);
        std::memcpy(reinterpret_cast<uint128_t*>(buf) + (nblock - 1), &padding,
                    padding_bytes);
      } else {
        std::vector<uint128_t> cipher(nblock);
        auto s = absl::MakeSpan(cipher);
        internal::EcbMakeContentBlocks(count, s);
        crypto->Encrypt(s, s);
        std::memcpy(buf, cipher.data(), nbytes);
      }
    }
  }
  return count + nblock;
}

}  // namespace yacl::crypto
