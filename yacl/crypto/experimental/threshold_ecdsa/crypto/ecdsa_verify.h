#pragma once

#include <cstdint>
#include <span>

#include "yacl/crypto/experimental/threshold_ecdsa/crypto/ec_point.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/scalar.h"

namespace tecdsa {

// Verify secp256k1 ECDSA by the standard equation:
//   R' = (m * s^-1)G + (r * s^-1)Y, accept iff r == x(R') mod q.
bool VerifyEcdsaSignatureMath(const ECPoint& public_key,
                              std::span<const uint8_t> msg32,
                              const Scalar& r,
                              const Scalar& s);

}  // namespace tecdsa
