#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "yacl/crypto/experimental/threshold_ecdsa/common/bytes.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/ec_point.h"
#include "yacl/math/mpint/mp_int.h"

namespace tecdsa {

using BigInt = yacl::math::MPInt;

Bytes EncodeMpInt(const BigInt& value);
BigInt DecodeMpInt(std::span<const uint8_t> encoded, size_t max_len = 8192);

Bytes EncodePoint(const ECPoint& point);
ECPoint DecodePoint(std::span<const uint8_t> encoded);

}  // namespace tecdsa
