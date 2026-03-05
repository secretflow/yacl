#include "yacl/crypto/experimental/threshold_ecdsa/crypto/encoding.h"
#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"

#include <string>
#include <stdexcept>

#include "yacl/crypto/experimental/threshold_ecdsa/crypto/bigint_utils.h"

namespace tecdsa {
namespace {

void AppendU32Be(uint32_t value, Bytes* out) {
  out->push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
  out->push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
  out->push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
  out->push_back(static_cast<uint8_t>(value & 0xFF));
}

uint32_t ReadU32Be(std::span<const uint8_t> input, size_t offset) {
  if (offset + 4 > input.size()) {
    TECDSA_THROW_ARGUMENT("Not enough bytes to read u32");
  }

  return (static_cast<uint32_t>(input[offset]) << 24) |
         (static_cast<uint32_t>(input[offset + 1]) << 16) |
         (static_cast<uint32_t>(input[offset + 2]) << 8) |
         static_cast<uint32_t>(input[offset + 3]);
}

BigInt MpzToMpInt(const mpz_class& value) {
  return BigInt(value.get_str(10), 10);
}

mpz_class MpIntToMpz(const BigInt& value) {
  mpz_class out;
  const std::string decimal = value.ToString();
  if (mpz_set_str(out.get_mpz_t(), decimal.c_str(), 10) != 0) {
    TECDSA_THROW("failed to convert MPInt to mpz_class");
  }
  return out;
}

}  // namespace

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

  const uint32_t payload_len = ReadU32Be(encoded, 0);
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

Bytes EncodeMpz(const mpz_class& value) {
  return EncodeMpInt(MpzToMpInt(value));
}

mpz_class DecodeMpz(std::span<const uint8_t> encoded, size_t max_len) {
  return MpIntToMpz(DecodeMpInt(encoded, max_len));
}

Bytes EncodePoint(const ECPoint& point) {
  return point.ToCompressedBytes();
}

ECPoint DecodePoint(std::span<const uint8_t> encoded) {
  return ECPoint::FromCompressed(encoded);
}

}  // namespace tecdsa
