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


#include "yasl/crypto/hmac.h"

#include "openssl/evp.h"

#include "yasl/base/exception.h"
#include "yasl/utils/scope_guard.h"

namespace yasl::crypto {

namespace {

void Init_HMAC(HashAlgorithm hash_algo, ByteContainerView key,
               HMAC_CTX* context) {
  int res = 0;
  switch (hash_algo) {
    case HashAlgorithm::SHA224:
      res =
          HMAC_Init_ex(context, key.data(), key.size(), EVP_sha224(), nullptr);
      break;
    case HashAlgorithm::SHA256:
      res =
          HMAC_Init_ex(context, key.data(), key.size(), EVP_sha256(), nullptr);
      break;
    case HashAlgorithm::SHA384:
      res =
          HMAC_Init_ex(context, key.data(), key.size(), EVP_sha384(), nullptr);
      break;
    case HashAlgorithm::SHA512:
      res =
          HMAC_Init_ex(context, key.data(), key.size(), EVP_sha512(), nullptr);
      break;
    case HashAlgorithm::SHA_1:
      res = HMAC_Init_ex(context, key.data(), key.size(), EVP_sha1(), nullptr);
      break;
    case HashAlgorithm::SM3:
      res = HMAC_Init_ex(context, key.data(), key.size(), EVP_sm3(), nullptr);
      break;
    case HashAlgorithm::UNKNOWN:
    default:
      YASL_THROW("Unsupported hash algo: {}", static_cast<int>(hash_algo));
      break;
  }

  YASL_ENFORCE_EQ(res, 1, "Failed to HMAC_Init_ex.");
}

}  // namespace

Hmac::Hmac(HashAlgorithm hash_algo, ByteContainerView key)
    : hash_algo_(hash_algo),
      key_(key.begin(), key.end()),
      context_(CheckNotNull(HMAC_CTX_new())) {
  Reset();
}

Hmac::~Hmac() { HMAC_CTX_free(context_); }

HashAlgorithm Hmac::GetHashAlgorithm() const { return hash_algo_; }

Hmac& Hmac::Reset() {
  YASL_ENFORCE_EQ(HMAC_CTX_reset(context_), 1);
  Init_HMAC(hash_algo_, key_, context_);
  return *this;
}

Hmac& Hmac::Update(ByteContainerView data) {
  YASL_ENFORCE(HMAC_Update(context_, data.data(), data.size()) == 1, "HMAC_Update failed");
  return *this;
}

std::vector<uint8_t> Hmac::CumulativeMac() const {
  // Do not finalize the internally stored hash context. Instead, finalize a
  // copy of the current context so that the current context can be updated in
  // future calls to Update.
  HMAC_CTX* context_snapshot = HMAC_CTX_new();
  YASL_ENFORCE(context_snapshot != nullptr);
  ON_SCOPE_EXIT([&] { HMAC_CTX_free(context_snapshot); });
  Init_HMAC(hash_algo_, key_, context_snapshot);
  YASL_ENFORCE_EQ(HMAC_CTX_copy(context_snapshot, context_), 1);
  size_t mac_size = HMAC_size(context_snapshot);
  YASL_ENFORCE_GT(mac_size, (size_t)0);
  std::vector<uint8_t> mac(mac_size);
  unsigned int len;
  YASL_ENFORCE_EQ(HMAC_Final(context_snapshot, mac.data(), &len), 1);
  // Correct the mac size if needed.
  if (mac_size != len) {
    mac.resize(len);
  }

  return mac;
}

}  // namespace yasl::crypto
