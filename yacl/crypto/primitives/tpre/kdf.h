#ifndef CRYPTO_SM3_H_
#define CRYPTO_SM3_H_
#include <memory>

#include "yacl/crypto/base/hash/hash_utils.h"

namespace yacl::crypto {

/// @brief Implementing key-derived functions via Sm3
/// @param Z, a random value
/// @param key_len, the key length
/// @return key
std::vector<uint8_t> KDF(absl::string_view Z, size_t key_len);

}  // namespace yacl::crypto

#endif  // CRYPTO_SM3_H_
