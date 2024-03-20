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

#include "yacl/crypto/hash/ssl_hash.h"

#include "yacl/base/exception.h"
#include "yacl/crypto/openssl_wrappers.h"
#include "yacl/utils/scope_guard.h"

namespace yacl::crypto {

SslHash::SslHash(HashAlgorithm hash_algo)
    : hash_algo_(hash_algo),
      md_(openssl::FetchEvpMd(ToString(hash_algo))),
      context_(EVP_MD_CTX_new()),
      digest_size_(EVP_MD_size(md_.get())) {
  Reset();
}

HashAlgorithm SslHash::GetHashAlgorithm() const { return hash_algo_; }

size_t SslHash::DigestSize() const { return digest_size_; }

SslHash& SslHash::Reset() {
  OSSL_RET_1(EVP_MD_CTX_reset(context_.get()));
  int res = 0;
  const auto md = openssl::FetchEvpMd(ToString(hash_algo_));
  res = EVP_DigestInit_ex(context_.get(), md.get(), nullptr);
  OSSL_RET_1(res, "EVP_DigestInit_ex failed.");

  return *this;
}

SslHash& SslHash::Update(ByteContainerView data) {
  OSSL_RET_1(EVP_DigestUpdate(context_.get(), data.data(), data.size()));
  return *this;
}

std::vector<uint8_t> SslHash::CumulativeHash() const {
  unsigned int out_len = 0;
  std::vector<uint8_t> out(DigestSize());
  // Do not finalize the internally stored hash context. Instead, finalize a
  // copy of the current context so that the current context can be updated in
  // future calls to Update.
  auto ctx_snapshot = openssl::UniqueMdCtx(EVP_MD_CTX_new());
  YACL_ENFORCE(ctx_snapshot != nullptr);

  EVP_MD_CTX_init(ctx_snapshot.get());  // no return value

  OSSL_RET_1(EVP_MD_CTX_copy_ex(ctx_snapshot.get(), context_.get()));
  OSSL_RET_1(EVP_DigestFinal_ex(ctx_snapshot.get(), out.data(), &out_len));

  YACL_ENFORCE(out_len == DigestSize());

  return out;
}

}  // namespace yacl::crypto
