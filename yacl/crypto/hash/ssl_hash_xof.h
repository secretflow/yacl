// Copyright 2025 Ant Group Co., Ltd.
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

#include "yacl/base/byte_container_view.h"
#include "yacl/crypto/hash/hash_interface.h"
#include "yacl/crypto/openssl_wrappers.h"

namespace yacl::crypto {

class SslHashXof : public HashInterface {
 public:
  explicit SslHashXof(HashAlgorithm hash_algo);
  // From HashInterface.
  HashAlgorithm GetHashAlgorithm() const override { return hash_algo_; }
  size_t DigestSize() const override { return digest_size_; }
  HashInterface& Reset() override;
  HashInterface& Update(ByteContainerView data) override;
  std::vector<uint8_t> CumulativeHash() const override;

  // For XOF hash functions, this method allows requesting a specific output
  // length.
  std::vector<uint8_t> CumulativeHash(size_t output_length) const;

 private:
  HashAlgorithm hash_algo_;
  openssl::UniqueMd md_;
  openssl::UniqueMdCtx context_;
  size_t digest_size_ = 32;
};

// Shake128Hash implements HashInterface for the Shake128 hash function,
// which is an extendable-output function (XOF) defined in FIPS 202.
// SHAKE128 allows for variable-length output.
class Shake128Hash final : public SslHashXof {
 public:
  Shake128Hash() : SslHashXof(HashAlgorithm::SHAKE128) {}
};

// Shake256Hash implements HashInterface for the Shake256 hash function,
// which is an extendable-output function (XOF) defined in FIPS 202.
// SHAKE256 allows for variable-length output.
class Shake256Hash final : public SslHashXof {
 public:
  Shake256Hash() : SslHashXof(HashAlgorithm::SHAKE256) {}
};

}  // namespace yacl::crypto