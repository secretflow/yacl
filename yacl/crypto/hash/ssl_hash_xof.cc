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

#include "yacl/crypto/hash/ssl_hash_xof.h"

#include <openssl/evp.h>

#include "yacl/base/exception.h"

namespace yacl::crypto {

SslHashXof::SslHashXof(HashAlgorithm hash_algo)
    : hash_algo_(hash_algo),
      md_(openssl::FetchEvpMd(ToString(hash_algo))),
      context_(EVP_MD_CTX_new()) {
  YACL_ENFORCE(context_ != nullptr, "Failed to create EVP_MD_CTX");
  YACL_ENFORCE(EVP_DigestInit_ex(context_.get(), md_.get(), nullptr) == 1,
               "Failed to initialize XOF hash");
  switch (hash_algo) {
    case HashAlgorithm::SHAKE128:
      digest_size_ = 32;
      break;
    case HashAlgorithm::SHAKE256:
      digest_size_ = 64;
      break;
    default:
      YACL_THROW("Unsupported XOF algorithm: {}", static_cast<int>(hash_algo));
  }
}

HashInterface& SslHashXof::Reset() {
  OSSL_RET_1(EVP_DigestInit_ex(context_.get(), md_.get(), nullptr));
  return *this;
}

HashInterface& SslHashXof::Update(ByteContainerView data) {
  OSSL_RET_1(EVP_DigestUpdate(context_.get(), data.data(), data.size()));
  return *this;
}

std::vector<uint8_t> SslHashXof::CumulativeHash() const {
  return CumulativeHash(digest_size_);
}

std::vector<uint8_t> SslHashXof::CumulativeHash(size_t output_length) const {
  std::vector<uint8_t> output(output_length);
  auto ctx_snapshot = openssl::UniqueMdCtx(EVP_MD_CTX_new());
  YACL_ENFORCE(ctx_snapshot != nullptr);

  EVP_MD_CTX_init(ctx_snapshot.get());
  OSSL_RET_1(EVP_MD_CTX_copy_ex(ctx_snapshot.get(), context_.get()));
  OSSL_RET_1(
      EVP_DigestFinalXOF(ctx_snapshot.get(), output.data(), output_length));

  return output;
}

}  // namespace yacl::crypto