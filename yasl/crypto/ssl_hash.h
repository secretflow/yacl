#pragma once

#include "openssl/evp.h"

#include "yasl/base/byte_container_view.h"
#include "yasl/crypto/hash_interface.h"

namespace yasl::crypto {

// Abstract hash implements HashInterface.
class SslHash : public HashInterface {
 public:
  explicit SslHash(HashAlgorithm hash_algo);
  ~SslHash() override;

  // From HashInterface.
  HashAlgorithm GetHashAlgorithm() const override;
  size_t DigestSize() const override;
  SslHash& Reset() override;
  SslHash& Update(ByteContainerView data) override;
  std::vector<uint8_t> CumulativeHash() const override;

 private:
  const HashAlgorithm hash_algo_;
  const size_t digest_size_;
  EVP_MD_CTX* context_;
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

}  // namespace yasl::crypto
