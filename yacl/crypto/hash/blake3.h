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

#pragma once

#include <vector>

#include "c/blake3.h"

#include "yacl/base/byte_container_view.h"
#include "yacl/crypto/hash/hash_interface.h"

namespace yacl::crypto {
// specification document of the blake3 hash function
// https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf
// https://github.com/BLAKE3-team/BLAKE3
// blake3 hash implements HashInterface.
//
// Notice: output_len would affect security level (default output_len = 32, 256
// bits). An N-bits Blake3 would provide N bits of first and second preimage
// resistance and N/2 bits of collision resistance (N <= 256).
//
// For more discussions, see:
// 1. https://github.com/BLAKE3-team/BLAKE3/blob/master/c/README.md Security
// Notes
// 2. https://github.com/BLAKE3-team/BLAKE3/issues/194
// 3. https://github.com/BLAKE3-team/BLAKE3/issues/278
//
class Blake3Hash : public HashInterface {
 public:
  Blake3Hash();
  explicit Blake3Hash(size_t output_len);
  ~Blake3Hash() override;

  // From HashInterface.
  HashAlgorithm GetHashAlgorithm() const override;
  size_t DigestSize() const override;
  Blake3Hash& Reset() override;
  Blake3Hash& Update(ByteContainerView data) override;
  std::vector<uint8_t> CumulativeHash() const override;

 private:
  const HashAlgorithm hash_algo_;
  const size_t digest_size_;
  blake3_hasher hasher_ctx_;

  void Init();
};
}  // namespace yacl::crypto
