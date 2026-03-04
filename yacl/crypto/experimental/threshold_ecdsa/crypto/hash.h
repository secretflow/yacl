#pragma once

#include <span>

#include "yacl/crypto/experimental/threshold_ecdsa/common/bytes.h"

namespace tecdsa {

Bytes Sha256(std::span<const uint8_t> data);
Bytes Sha512(std::span<const uint8_t> data);

}  // namespace tecdsa
