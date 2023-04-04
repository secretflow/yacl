#ifndef TPRE_HASH_H_
#define TPRE_HASH_H_
#include <stdint.h>
#include <string.h>

#include "yacl/crypto/base/ecc/ec_point.h"  //yacl ec_point
#include "yacl/crypto/base/ecc/ecc_spi.h"
#include "yacl/crypto/base/mpint/mp_int.h"  //yacl big number

namespace yacl::crypto {

/// @brief Cryptographic hash function, h_x = 1 + Bignum(sm3(x)||sm3(sm3(x))),
///        where n is the degree of EC Group, and x is input mod n-1
/// @param input
/// @param curve_id, elliptic curve type
/// @return hash value
MPInt CipherHash(absl::string_view input, std::string curve_type);
}  // namespace yacl::crypto

#endif  // TPRE_HASH_H_