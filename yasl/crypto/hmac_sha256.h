#pragma once

#include "yasl/crypto/hmac.h"

namespace yasl::crypto {

class HmacSha256 final : public Hmac {
 public:
  HmacSha256(ByteContainerView key) : Hmac(HashAlgorithm::SHA256, key) {}
};

}  // namespace yasl::crypto
