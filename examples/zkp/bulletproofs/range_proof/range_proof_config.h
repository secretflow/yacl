#pragma once

#include <memory>
#include <string>
#include <vector>

#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/math/mpint/mp_int.h"

namespace examples::zkp {

// Constants for the curve used in range proof
inline constexpr const char* kRangeProofEcName = "secp256k1";
inline constexpr const char* kRangeProofEcLib = "openssl";



}  // namespace examples::zkp 