#include "yasl/crypto/ssl_hash.h"

#include "yasl/base/exception.h"
#include "yasl/utils/scope_guard.h"

namespace yasl::crypto {

const EVP_MD* CreateEvpMD(HashAlgorithm hash_algo_) {
  switch (hash_algo_) {
    case HashAlgorithm::SHA224:
    case HashAlgorithm::SHA256:
      return EVP_sha256();
    case HashAlgorithm::SHA384:
      return EVP_sha384();
    case HashAlgorithm::SHA512:
      return EVP_sha512();
    case HashAlgorithm::SHA_1:
      return EVP_sha1();
    case HashAlgorithm::SM3:
      return EVP_sm3();
    case HashAlgorithm::BLAKE2B:
      return EVP_blake2b512();
    default:
      YASL_THROW("Unsupported hash algo: {}", static_cast<int>(hash_algo_));
  }
}

SslHash::SslHash(HashAlgorithm hash_algo)
    : hash_algo_(hash_algo),
      digest_size_(EVP_MD_size(CreateEvpMD(hash_algo))),
      context_(CheckNotNull(EVP_MD_CTX_new())) {
  Reset();
}

SslHash::~SslHash() { EVP_MD_CTX_free(context_); }

HashAlgorithm SslHash::GetHashAlgorithm() const { return hash_algo_; }

size_t SslHash::DigestSize() const { return digest_size_; }

SslHash& SslHash::Reset() {
  YASL_ENFORCE_EQ(EVP_MD_CTX_reset(context_), 1);
  int res = 0;
  const EVP_MD* md = CreateEvpMD(hash_algo_);
  res = EVP_DigestInit_ex(context_, md, nullptr);
  YASL_ENFORCE_EQ(res, 1, "EVP_DigestInit_ex failed.");

  return *this;
}

SslHash& SslHash::Update(ByteContainerView data) {
  YASL_ENFORCE_EQ(EVP_DigestUpdate(context_, data.data(), data.size()), 1);
  return *this;
}

std::vector<uint8_t> SslHash::CumulativeHash() const {
  // Do not finalize the internally stored hash context. Instead, finalize a
  // copy of the current context so that the current context can be updated in
  // future calls to Update.
  EVP_MD_CTX* context_snapshot = EVP_MD_CTX_new();
  YASL_ENFORCE(context_snapshot != nullptr);
  ON_SCOPE_EXIT([&] { EVP_MD_CTX_free(context_snapshot); });
  EVP_MD_CTX_init(context_snapshot);
  YASL_ENFORCE_EQ(EVP_MD_CTX_copy_ex(context_snapshot, context_), 1);
  std::vector<uint8_t> digest(DigestSize());
  unsigned int digest_len;
  YASL_ENFORCE_EQ(
      EVP_DigestFinal_ex(context_snapshot, digest.data(), &digest_len), 1);
  YASL_ENFORCE_EQ(digest_len, DigestSize());

  return digest;
}

}  // namespace yasl::crypto
