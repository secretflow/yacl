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

#include <vector>

#include "yacl/base/byte_container_view.h"
#include "yacl/crypto/hash/hash_interface.h"
#include "yacl/crypto/openssl_wrappers.h"

namespace yacl::crypto {

// Abstract hash implements HashInterface.
class SslHash : public HashInterface {
 public:
  explicit SslHash(HashAlgorithm hash_algo);

  // From HashInterface.
  HashAlgorithm GetHashAlgorithm() const override;
  size_t DigestSize() const override;
  SslHash& Reset() override;
  SslHash& Update(ByteContainerView data) override;
  std::vector<uint8_t> CumulativeHash() const override;

 private:
  const HashAlgorithm hash_algo_;
  openssl::UniqueMd md_;
  openssl::UniqueMdCtx context_;
  const size_t digest_size_;
};

// Sm3Hash implements HashInterface for the SM3 hash function.
class Sm3Hash final : public SslHash {
 public:
  Sm3Hash() : SslHash(HashAlgorithm::SM3) {}
};

// Sha256Hash implements HashInterface for the SHA-256 hash function.
class Sha256Hash final : public SslHash {
 public:
  Sha256Hash() : SslHash(HashAlgorithm::SHA256) {}
};

// Blake2Hash implements HashInterface for the Blake2b512 hash function.
class Blake2Hash final : public SslHash {
 public:
  Blake2Hash() : SslHash(HashAlgorithm::BLAKE2B) {}
};

}  // namespace yacl::crypto
