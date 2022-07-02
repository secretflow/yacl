#pragma once

#include "yasl/crypto/hmac.h"

namespace yasl::crypto {

class HmacSm3 final : public Hmac {
 public:
  HmacSm3(ByteContainerView key) : Hmac(HashAlgorithm::SM3, key) {}
};

}  // namespace yasl::crypto
