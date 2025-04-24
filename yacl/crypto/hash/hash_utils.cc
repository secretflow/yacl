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

#include "yacl/crypto/hash/hash_utils.h"

#include <cstring>
#include <iostream>
#include <vector>

#include "c/blake3.h"

#include "yacl/base/byte_container_view.h"
#include "yacl/base/exception.h"
#include "yacl/crypto/hash/ssl_hash.h"
#include "yacl/crypto/hash/ssl_hash_xof.h"

namespace yacl::crypto {

std::array<uint8_t, 32> Sha256(ByteContainerView data) {
  auto buf = SslHash(HashAlgorithm::SHA256).Update(data).CumulativeHash();
  YACL_ENFORCE(buf.size() >= 32);
  std::array<uint8_t, 32> out{};
  memcpy(out.data(), buf.data(), 32);
  return out;
}

std::array<uint8_t, 32> Sm3(ByteContainerView data) {
  auto buf = SslHash(HashAlgorithm::SM3).Update(data).CumulativeHash();
  YACL_ENFORCE(buf.size() >= 32);
  std::array<uint8_t, 32> out{};
  memcpy(out.data(), buf.data(), 32);
  return out;
}

std::vector<uint8_t> Shake128(ByteContainerView data, size_t output_length) {
  YACL_ENFORCE(output_length > 0, "Output length must be positive");
  SslHashXof hash(HashAlgorithm::SHAKE128);
  hash.Update(data);
  return hash.CumulativeHash(output_length);
}

std::vector<uint8_t> Shake256(ByteContainerView data, size_t output_length) {
  YACL_ENFORCE(output_length > 0, "Output length must be positive");
  SslHashXof hash(HashAlgorithm::SHAKE256);
  hash.Update(data);
  return hash.CumulativeHash(output_length);
}

#ifndef YACL_WITH_TONGSUO
std::array<uint8_t, 64> Blake2(ByteContainerView data) {
  auto buf = SslHash(HashAlgorithm::BLAKE2B).Update(data).CumulativeHash();
  YACL_ENFORCE(buf.size() >= 64);
  std::array<uint8_t, 64> out{};
  memcpy(out.data(), buf.data(), 64);
  return out;
}
#endif

std::array<uint8_t, 32> Blake3(ByteContainerView data) {
  YACL_ENFORCE(BLAKE3_OUT_LEN == 32);
  blake3_hasher hasher;
  blake3_hasher_init(&hasher);
  blake3_hasher_update(&hasher, data.data(), data.size());
  std::array<uint8_t, BLAKE3_OUT_LEN> digest{};
  blake3_hasher_finalize(&hasher, digest.data(), BLAKE3_OUT_LEN);
  return digest;
}

}  // namespace yacl::crypto
