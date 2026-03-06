// Copyright 2026 Ant Group Co., Ltd.
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

#include "yacl/crypto/experimental/threshold_ecdsa/crypto/hash.h"

#include <openssl/sha.h>

#include <array>
#include <stdexcept>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"

namespace tecdsa {

Bytes Sha256(std::span<const uint8_t> data) {
  std::array<uint8_t, SHA256_DIGEST_LENGTH> digest{};
  if (SHA256(data.data(), data.size(), digest.data()) == nullptr) {
    TECDSA_THROW("SHA256 failed");
  }
  return Bytes(digest.begin(), digest.end());
}

Bytes Sha512(std::span<const uint8_t> data) {
  std::array<uint8_t, SHA512_DIGEST_LENGTH> digest{};
  if (SHA512(data.data(), data.size(), digest.data()) == nullptr) {
    TECDSA_THROW("SHA512 failed");
  }
  return Bytes(digest.begin(), digest.end());
}

}  // namespace tecdsa
