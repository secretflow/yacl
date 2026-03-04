#include "yacl/crypto/experimental/threshold_ecdsa/crypto/hash.h"
#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"

#include <array>
#include <stdexcept>

#include <openssl/sha.h>

namespace tecdsa {

Bytes Sha256(std::span<const uint8_t> data) {
  std::array<uint8_t, SHA256_DIGEST_LENGTH> digest{};
  if (SHA256(data.data(), data.size(), digest.data()) == nullptr) {
    TECDSA_THROW("SHA256 failed");
  }
  return Bytes(digest.begin(), digest.end());
}

Bytes Sha512(std::span<const uint8_t> data) {
  std::array<uint8_t, SHA512_DIGEST_LENGTH> digest{};
  if (SHA512(data.data(), data.size(), digest.data()) == nullptr) {
    TECDSA_THROW("SHA512 failed");
  }
  return Bytes(digest.begin(), digest.end());
}

}  // namespace tecdsa
