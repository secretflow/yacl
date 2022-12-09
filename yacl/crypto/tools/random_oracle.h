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

#include <fmt/core.h>

#include <array>
#include <cstring>
#include <vector>

#include "yacl/base/buffer.h"
#include "yacl/base/exception.h"
#include "yacl/crypto/base/hash/hash_utils.h"

namespace yacl {

// This is a implementation of the **theoretical tool**: Random oracle.
//
// [Random-oracle methodology]: For “natural” applications of hash functions,
// the concrete security proven in the random-oracle model is the right bound
// even in the standard model, assuming the “best possible” concrete hash
// function H is chosen.
//
// [WARNING] Theoretically we don't know if there are good random oracle
// implementation, instantiating RO with hash function may have potential
// security issues, please use at your own risk.
//
// Discussions:
//  - https://crypto.stackexchange.com/a/880/61581
//  - https://arxiv.org/pdf/cs/0010019.pdf
//
// Papers:
//  - The Random Oracle Methodology, Revisited: https://eprint.iacr.org/1998/011
//  - Random Oracles and Non-uniformity: https://eprint.iacr.org/2017/937
//
// We use the following single-function to instantiate RO (although there are
// security concerns, see: https://eprint.iacr.org/1998/011.pdf):
//  1. SHA256 (with 32 bytes output)
//  2. SM3 (with 32 bytes output)
//  3. BLAKE2B (with 64 bytes output)
//  4. BLAKE3 (with 32 bytes output)
//
// TODO(@shanzhu): Implement RO by a function ensemble

class RandomOracle {
 public:
  explicit RandomOracle(crypto::HashAlgorithm hash_type, size_t outlen = 16)
      : outlen_(outlen), hash_alg_(hash_type) {
    SanityCheck();
  }

  // Apply Random Oracle on a given buffer array
  // fixed output size = 32 (256bits)
  Buffer operator()(ByteContainerView x, size_t outlen) const {
    switch (hash_alg_) {
      case crypto::HashAlgorithm::SHA256:  // outlen = 32 (256bits)
        YACL_ENFORCE(outlen <= 32);
        return {crypto::Sha256(x).data(), outlen};
      case crypto::HashAlgorithm::SM3:  // outlen = 32 (256bits)
        YACL_ENFORCE(outlen <= 32);
        return {crypto::Sm3(x).data(), outlen};
      case crypto::HashAlgorithm::BLAKE2B:  // outlen = 64 (512bits)
        YACL_ENFORCE(outlen <= 64);
        return {crypto::Blake2(x).data(), outlen};
      case crypto::HashAlgorithm::BLAKE3:
        YACL_ENFORCE(outlen <= 32);  // outlen = 32 (256bits)
        return {crypto::Blake3(x).data(), outlen};
      default:
        YACL_THROW("Unsupported hash algorithm: {}",
                   static_cast<int>(hash_alg_));
    }
  }

  Buffer Gen(ByteContainerView x) const {
    return operator()(x, outlen_);
  }

  template <typename T, std::enable_if_t<std::is_standard_layout_v<T>, int> = 0>
  T Gen(ByteContainerView x) const {
    T res;                                // max bits of sizeof(T) = 16
    auto buf = operator()(x, sizeof(T));  // min bits of sizeof(T) = 32
    std::memcpy(&res, buf.data(), sizeof(T));
    return res;
  }

  template <typename T, std::enable_if_t<std::is_standard_layout_v<T>, int> = 0>
  T Gen(ByteContainerView x, uint64_t y) const {
    auto buf_size = x.size() + sizeof(uint64_t);
    Buffer buf(buf_size);
    std::memcpy(static_cast<std::byte*>(buf.data()), x.data(), x.size());
    std::memcpy(static_cast<std::byte*>(buf.data()) + x.size(), &y,
                sizeof(uint64_t));
    return Gen<T>(buf);
  }

  void SetOutlen(size_t out_len) {
    outlen_ = out_len;
    SanityCheck();
  }

  size_t GetOutlen() const { return outlen_; }

  void SanityCheck() {
    YACL_ENFORCE(outlen_ > 0);
    if (hash_alg_ == crypto::HashAlgorithm::SHA256 ||
        hash_alg_ == crypto::HashAlgorithm::SM3 ||
        hash_alg_ == crypto::HashAlgorithm::BLAKE3) {
      YACL_ENFORCE(outlen_ <= 32);
    } else if (hash_alg_ == crypto::HashAlgorithm::BLAKE2B) {
      YACL_ENFORCE(outlen_ <= 64);
    } else {
      YACL_THROW("Unsupported hash algorithm: {}", static_cast<int>(hash_alg_));
    }
  }

  static RandomOracle& GetBlake3() {
    static RandomOracle ro(crypto::HashAlgorithm::BLAKE3, 16);
    return ro;
  }

  static RandomOracle& GetSm3() {
    static RandomOracle ro(crypto::HashAlgorithm::SM3, 16);
    return ro;
  }

  // Default random oracle outputs a block (128 bits) with blake3 hash
  static RandomOracle& GetDefault() { return GetBlake3(); }

 private:
  size_t outlen_;
  crypto::HashAlgorithm hash_alg_;
};

inline uint128_t RO_Blake3_128(ByteContainerView in) {
  return RandomOracle::GetBlake3().Gen<uint128_t>(in);
};

inline uint128_t RO_SM3_128(ByteContainerView in) {
  return RandomOracle::GetSm3().Gen<uint128_t>(in);
};

}  // namespace yacl
