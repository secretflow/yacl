// Copyright 2026 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "yacl/crypto/experimental/threshold_ecdsa/crypto/encoding.h"

#include <stdexcept>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/bigint_utils.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/byte_io.h"

namespace tecdsa {

Bytes EncodeMpInt(const BigInt& value) {
  const Bytes payload = bigint::ToBigEndian(value);

  if (payload.size() > UINT32_MAX) {
    TECDSA_THROW_ARGUMENT("mpz byte length exceeds uint32");
  }

  Bytes out;
  out.reserve(4 + payload.size());
  AppendU32Be(static_cast<uint32_t>(payload.size()), &out);
  out.insert(out.end(), payload.begin(), payload.end());
  return out;
}

BigInt DecodeMpInt(std::span<const uint8_t> encoded, size_t max_len) {
  if (encoded.size() < 4) {
    TECDSA_THROW_ARGUMENT("Encoded mpz is too short");
  }

  const uint32_t payload_len = ReadU32Be(encoded, size_t{0});
  if (payload_len == 0) {
    TECDSA_THROW_ARGUMENT("Encoded mpz payload length must be >= 1");
  }
  if (payload_len > max_len) {
    TECDSA_THROW_ARGUMENT("Encoded mpz payload exceeds max_len");
  }
  if (encoded.size() != 4 + payload_len) {
    TECDSA_THROW_ARGUMENT("Encoded mpz has inconsistent payload length");
  }

  return bigint::FromBigEndian(encoded.subspan(4, payload_len));
}

Bytes EncodePoint(const ECPoint& point) { return point.ToCompressedBytes(); }

ECPoint DecodePoint(std::span<const uint8_t> encoded) {
  return ECPoint::FromCompressed(encoded);
}

}  // namespace tecdsa
